/*! \file gprs_ns2_frgre.c
 * NS-over-FR-over-GRE implementation.
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2009-2010,2014,2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2020 sysmocom - s.f.m.c. GmbH
 * Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_ns2.h>

#include "gprs_ns2_internal.h"

#define GRE_PTYPE_FR	0x6559
#define GRE_PTYPE_IPv4	0x0800
#define GRE_PTYPE_IPv6	0x86dd
#define GRE_PTYPE_KAR	0x0000	/* keepalive response */

#ifndef IPPROTO_GRE
# define IPPROTO_GRE 47
#endif

struct gre_hdr {
	uint16_t flags;
	uint16_t ptype;
} __attribute__ ((packed));

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__CYGWIN__)
/**
 * On BSD the IPv4 struct is called struct ip and instead of iXX
 * the members are called ip_XX. One could change this code to use
 * struct ip but that would require to define _BSD_SOURCE and that
 * might have other complications. Instead make sure struct iphdr
 * is present on FreeBSD. The below is taken from GLIBC.
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
struct iphdr
  {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif BYTE_ORDER == BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };
#endif


static void free_bind(struct gprs_ns2_vc_bind *bind);
static inline int frgre_sendmsg(struct gprs_ns2_vc_bind *bind,
			       struct msgb *msg,
			       struct osmo_sockaddr *dest);

struct gprs_ns2_vc_driver vc_driver_frgre = {
	.name = "GB frame relay over GRE",
	.free_bind = free_bind,
};

struct priv_bind {
	struct osmo_fd fd;
	struct osmo_sockaddr addr;
	uint16_t dlci;
	int dscp;
};

struct priv_vc {
	struct osmo_sockaddr remote;
	uint16_t dlci;
};

static void free_vc(struct gprs_ns2_vc *nsvc)
{
	OSMO_ASSERT(nsvc);

	if (!nsvc->priv)
		return;

	talloc_free(nsvc->priv);
	nsvc->priv = NULL;
}


/*! clean up all private driver state. Should be only called by gprs_ns2_free_bind() */
static void free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (!bind)
		return;

	priv = bind->priv;

	OSMO_ASSERT(llist_empty(&bind->nsvc));

	osmo_fd_close(&priv->fd);
	talloc_free(priv);
}

static struct priv_vc *frgre_alloc_vc(struct gprs_ns2_vc_bind *bind,
				      struct gprs_ns2_vc *nsvc,
				      struct osmo_sockaddr *remote,
				      uint16_t dlci)
{
	struct priv_vc *priv = talloc_zero(bind, struct priv_vc);
	if (!priv)
		return NULL;

	nsvc->priv = priv;
	priv->remote = *remote;
	priv->dlci = dlci;

	return priv;
}

static int handle_rx_gre_ipv6(struct osmo_fd *bfd, struct msgb *msg,
			      struct ip6_hdr *ip6hdr, struct gre_hdr *greh)
{
	/* RFC 7676 IPv6 Support for Generic Routing Encapsulation (GRE) */
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct priv_bind *priv = bind->priv;
	int gre_payload_len;
	struct ip6_hdr *inner_ip6h;
	struct gre_hdr *inner_greh;
	struct sockaddr_in6 daddr;
	struct in6_addr ia6;

	gre_payload_len = msg->len - (sizeof(*ip6hdr) + sizeof(*greh));

	inner_ip6h = (struct ip6_hdr *) ((uint8_t *)greh + sizeof(*greh));

	if (gre_payload_len < sizeof(*ip6hdr) + sizeof(*inner_greh)) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive too short\n");
		return -EIO;
	}

	if (!memcmp(&inner_ip6h->ip6_src, &ip6hdr->ip6_src, sizeof(struct in6_addr)) ||
	    !memcmp(&inner_ip6h->ip6_dst, &ip6hdr->ip6_dst, sizeof(struct in6_addr))) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive with wrong tunnel addresses\n");
		return -EIO;
	}

	/* Are IPv6 extensions header are allowed in the *inner*? In the outer they are */
	if (inner_ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_GRE) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive with wrong protocol\n");
		return -EIO;
	}

	inner_greh = (struct gre_hdr *) ((uint8_t *)inner_ip6h + sizeof(struct ip6_hdr));
	if (inner_greh->ptype != osmo_htons(GRE_PTYPE_KAR)) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive inner GRE type != 0\n");
		return -EIO;
	}

	/* Actually send the response back */

	daddr.sin6_family = AF_INET6;
	daddr.sin6_addr = inner_ip6h->ip6_dst;
	daddr.sin6_port = IPPROTO_GRE;

	ia6 = ip6hdr->ip6_src;
	char ip6str[INET6_ADDRSTRLEN] = {};
	inet_ntop(AF_INET6, &ia6, ip6str, INET6_ADDRSTRLEN);
	LOGBIND(bind, LOGL_DEBUG, "GRE keepalive from %s, responding\n", ip6str);

	/* why does it reduce the gre_payload_len by the ipv6 header?
	 * make it similiar to ipv4 even this seems to be wrong */
	return sendto(priv->fd.fd, inner_greh,
		      gre_payload_len - sizeof(*inner_ip6h), 0,
		      (struct sockaddr *)&daddr, sizeof(daddr));
}

/* IPv4 messages inside the GRE tunnel might be GRE keepalives */
static int handle_rx_gre_ipv4(struct osmo_fd *bfd, struct msgb *msg,
			      struct iphdr *iph, struct gre_hdr *greh)
{
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct priv_bind *priv = bind->priv;
	int gre_payload_len;
	struct iphdr *inner_iph;
	struct gre_hdr *inner_greh;
	struct sockaddr_in daddr;
	struct in_addr ia;

	gre_payload_len = msg->len - (iph->ihl*4 + sizeof(*greh));

	inner_iph = (struct iphdr *) ((uint8_t *)greh + sizeof(*greh));

	if (gre_payload_len < inner_iph->ihl*4 + sizeof(*inner_greh)) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive too short\n");
		return -EIO;
	}

	if (inner_iph->saddr != iph->daddr ||
	    inner_iph->daddr != iph->saddr) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive with wrong tunnel addresses\n");
		return -EIO;
	}

	if (inner_iph->protocol != IPPROTO_GRE) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive with wrong protocol\n");
		return -EIO;
	}

	inner_greh = (struct gre_hdr *) ((uint8_t *)inner_iph + iph->ihl*4);
	if (inner_greh->ptype != osmo_htons(GRE_PTYPE_KAR)) {
		LOGBIND(bind, LOGL_ERROR, "GRE keepalive inner GRE type != 0\n");
		return -EIO;
	}

	/* Actually send the response back */

	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = inner_iph->daddr;
	daddr.sin_port = IPPROTO_GRE;

	ia.s_addr = iph->saddr;
	LOGBIND(bind, LOGL_DEBUG, "GRE keepalive from %s, responding\n", inet_ntoa(ia));

	/* why does it reduce the gre_payload_len by the ipv4 header? */
	return sendto(priv->fd.fd, inner_greh,
		      gre_payload_len - inner_iph->ihl*4, 0,
		      (struct sockaddr *)&daddr, sizeof(daddr));
}

static struct msgb *read_nsfrgre_msg(struct osmo_fd *bfd, int *error,
				     struct osmo_sockaddr *saddr, uint16_t *dlci,
				     const struct gprs_ns2_vc_bind *bind)
{
	struct msgb *msg = msgb_alloc(NS_ALLOC_SIZE, "Gb/NS/FR/GRE Rx");
	int ret = 0;
	socklen_t saddr_len = sizeof(*saddr);
	struct iphdr *iph = NULL;
	struct ip6_hdr *ip6h = NULL;
	size_t ip46hdr;
	struct gre_hdr *greh;
	uint8_t *frh;

	if (!msg) {
		*error = -ENOMEM;
		return NULL;
	}

	ret = recvfrom(bfd->fd, msg->data, NS_ALLOC_SIZE, 0,
			&saddr->u.sa, &saddr_len);
	if (ret < 0) {
		LOGBIND(bind, LOGL_ERROR, "recv error %s during NS-FR-GRE recv\n", strerror(errno));
		*error = ret;
		goto out_err;
	} else if (ret == 0) {
		*error = ret;
		goto out_err;
	}

	msgb_put(msg, ret);

	/* we've received a raw packet including the IPv4 or IPv6 header */
	switch (saddr->u.sa.sa_family) {
	case AF_INET:
		ip46hdr = sizeof(struct iphdr);
		break;
	case AF_INET6:
		ip46hdr = sizeof(struct ip6_hdr);
		break;
	default:
		*error = -EIO;
		goto out_err;
		break;
	}

	/* TODO: add support for the extension headers */
	if (msg->len < ip46hdr + sizeof(*greh) + 2) {
		LOGBIND(bind, LOGL_ERROR, "Short IP packet: %u bytes\n", msg->len);
		*error = -EIO;
		goto out_err;
	}

	switch (saddr->u.sa.sa_family) {
	case AF_INET:
		iph = (struct iphdr *) msg->data;
		if (msg->len < (iph->ihl*4 + sizeof(*greh) + 2)) {
			LOGBIND(bind, LOGL_ERROR, "Short IP packet: %u bytes\n", msg->len);
			*error = -EIO;
			goto out_err;
		}
		break;
	case AF_INET6:
		ip6h = (struct ip6_hdr *) msg->data;
		break;
	}

	if (iph)
		greh = (struct gre_hdr *) (msg->data + iph->ihl*4);
	else
		greh = (struct gre_hdr *) (msg->data + sizeof(struct ip6_hdr));

	if (greh->flags) {
		LOGBIND(bind, LOGL_NOTICE, "Unknown GRE flags 0x%04x\n", osmo_ntohs(greh->flags));
	}

	switch (osmo_ntohs(greh->ptype)) {
	case GRE_PTYPE_IPv4:
		/* IPv4 messages might be GRE keepalives */
		if (iph)
			*error = handle_rx_gre_ipv4(bfd, msg, iph, greh);
		else
			*error = -EIO;
		goto out_err;
		break;
	case GRE_PTYPE_IPv6:
		if (ip6h)
			*error = handle_rx_gre_ipv6(bfd, msg, ip6h, greh);
		else
			*error = -EIO;
		goto out_err;
		break;
	case GRE_PTYPE_FR:
		/* continue as usual */
		break;
	default:
		LOGBIND(bind, LOGL_NOTICE, "Unknown GRE protocol 0x%04x != FR\n", osmo_ntohs(greh->ptype));
		*error = -EIO;
		goto out_err;
		break;
	}

	if (msg->len < sizeof(*greh) + 2) {
		LOGBIND(bind, LOGL_ERROR, "Short FR header: %u bytes\n", msg->len);
		*error = -EIO;
		goto out_err;
	}

	frh = (uint8_t *)greh + sizeof(*greh);
	if (frh[0] & 0x01) {
		LOGBIND(bind, LOGL_NOTICE, "Unsupported single-byte FR address\n");
		*error = -EIO;
		goto out_err;
	}
	*dlci = ((frh[0] & 0xfc) << 2);
	if ((frh[1] & 0x0f) != 0x01) {
		LOGBIND(bind, LOGL_NOTICE, "Unknown second FR octet 0x%02x\n", frh[1]);
		*error = -EIO;
		goto out_err;
	}
	*dlci |= (frh[1] >> 4);

	msg->l2h = frh+2;

	return msg;

out_err:
	msgb_free(msg);
	return NULL;
}

static int ns2_find_vc_by_dlci(struct gprs_ns2_vc_bind *bind,
			       uint16_t dlci,
			       struct gprs_ns2_vc **result)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	if (!result)
		return -EINVAL;

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vcpriv = nsvc->priv;
		if (vcpriv->dlci != dlci) {
			*result = nsvc;
			return 0;
		}
	}

	return 1;
}

static int handle_nsfrgre_read(struct osmo_fd *bfd)
{
	int rc;
	struct osmo_sockaddr saddr;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct msgb *msg;
	struct msgb *reject;
	uint16_t dlci;

	msg = read_nsfrgre_msg(bfd, &rc, &saddr, &dlci, bind);
	if (!msg)
		return rc;

	if (dlci == 0 || dlci == 1023) {
		LOGBIND(bind, LOGL_INFO, "Received FR on LMI DLCI %u - ignoring\n", dlci);
		rc = 0;
		goto out;
	}

	rc = ns2_find_vc_by_dlci(bind, dlci, &nsvc);
	if (rc) {
		/* VC not found */
		rc = ns2_create_vc(bind, msg, &saddr, "newconnection", &reject, &nsvc);
		switch (rc) {
		case NS2_CS_FOUND:
			break;
		case NS2_CS_ERROR:
		case NS2_CS_SKIPPED:
			rc = 0;
			goto out;
		case NS2_CS_REJECTED:
			/* nsip_sendmsg will free reject */
			rc = frgre_sendmsg(bind, reject, &saddr);
			goto out;
		case NS2_CS_CREATED:
			frgre_alloc_vc(bind, nsvc, &saddr, dlci);
			ns2_vc_fsm_start(nsvc);
			break;
		}
	}

	rc = ns2_recv_vc(nsvc, msg);
out:
	msgb_free(msg);

	return rc;
}

static int handle_nsfrgre_write(struct osmo_fd *bfd)
{
	/* FIXME: actually send the data here instead of nsip_sendmsg() */
	return -EIO;
}

static inline int frgre_sendmsg(struct gprs_ns2_vc_bind *bind,
			       struct msgb *msg,
			       struct osmo_sockaddr *dest)
{
	int rc;
	struct priv_bind *priv = bind->priv;

	rc = sendto(priv->fd.fd, msg->data, msg->len, 0,
		    &dest->u.sa, sizeof(*dest));

	msgb_free(msg);

	return rc;
}

static int frgre_vc_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	struct gprs_ns2_vc_bind *bind = nsvc->bind;
	struct priv_vc *vcpriv = nsvc->priv;
	struct priv_bind *bindpriv = bind->priv;

	uint16_t dlci = osmo_htons(bindpriv->dlci);
	uint8_t *frh;
	struct gre_hdr *greh;

	/* Prepend the FR header */
	frh = msgb_push(msg, 2);
	frh[0] = (dlci >> 2) & 0xfc;
	frh[1] = ((dlci & 0xf)<<4) | 0x01;

	/* Prepend the GRE header */
	greh = (struct gre_hdr *) msgb_push(msg, sizeof(*greh));
	greh->flags = 0;
	greh->ptype = osmo_htons(GRE_PTYPE_FR);

	return frgre_sendmsg(bind, msg, &vcpriv->remote);
}

static int frgre_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & OSMO_FD_READ)
		rc = handle_nsfrgre_read(bfd);
	if (what & OSMO_FD_WRITE)
		rc = handle_nsfrgre_write(bfd);

	return rc;
}

/*! determine if given bind is for FR-GRE encapsulation. */
int gprs_ns2_is_frgre_bind(struct gprs_ns2_vc_bind *bind)
{
	return (bind->driver == &vc_driver_frgre);
}

/*! Create a new bind for NS over FR-GRE.
 *  \param[in] nsi NS instance in which to create the bind
 *  \param[in] local local address on which to bind
 *  \param[in] dscp DSCP/TOS bits to use for transmitted data on this bind
 *  \param[out] result pointer to the created bind or if a bind with the name exists return the bind.
 *  \return 0 on success; negative on error. -EALREADY returned in case a bind with the name exists */
int gprs_ns2_frgre_bind(struct gprs_ns2_inst *nsi,
			const char *name,
			const struct osmo_sockaddr *local,
			int dscp,
			struct gprs_ns2_vc_bind **result)
{
	struct gprs_ns2_vc_bind *bind;
	struct priv_bind *priv;
	int rc;

	if (local->u.sa.sa_family != AF_INET && local->u.sa.sa_family != AF_INET6)
		return -EINVAL;

	if (dscp < 0 || dscp > 63)
		return -EINVAL;

	bind = gprs_ns2_bind_by_name(nsi, name);
	if (bind) {
		if (result)
			*result = bind;
		return -EALREADY;
	}

	rc = ns2_bind_alloc(nsi, name, &bind);
	if (rc < 0)
		return rc;

	bind->driver = &vc_driver_frgre;
	bind->ll = GPRS_NS2_LL_FR_GRE;
	/* 2 mbit transfer capability. Counting should be done different for this. */
	bind->transfer_capability = 2;
	bind->send_vc = frgre_vc_sendmsg;
	bind->free_vc = free_vc;
	bind->nsi = nsi;
	/* TODO: allow to set the MTU via vty. It can not be automatic detected because it goes over an
	 * ethernet device and the MTU here must match the FR side of the FR-to-GRE gateway.
	 */
	bind->mtu = FRAME_RELAY_SDU;

	priv = bind->priv = talloc_zero(bind, struct priv_bind);
	if (!priv) {
		gprs_ns2_free_bind(bind);
		return -ENOMEM;
	}
	priv->fd.cb = frgre_fd_cb;
	priv->fd.data = bind;
	priv->addr = *local;
	INIT_LLIST_HEAD(&bind->nsvc);
	priv->dscp = dscp;

	rc = osmo_sock_init_osa_ofd(&priv->fd, SOCK_RAW, IPPROTO_GRE,
				 local, NULL,
				 OSMO_SOCK_F_BIND | OSMO_SOCK_F_DSCP(priv->dscp));
	if (rc < 0) {
		gprs_ns2_free_bind(bind);
		return rc;
	}

	if (result)
		*result = bind;

	return rc;
}
