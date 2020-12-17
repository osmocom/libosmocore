/*! \file gprs_ns2_fr.c
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
#include <net/if.h>

#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/hdlc.h>

#include <osmocom/gprs/frame_relay.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_ns2.h>

#ifdef ENABLE_LIBMNL
#include <osmocom/core/mnl.h>
#endif

#include "config.h"
#include "common_vty.h"
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

static void free_bind(struct gprs_ns2_vc_bind *bind);
static int fr_dlci_rx_cb(void *cb_data, struct msgb *msg);

struct gprs_ns2_vc_driver vc_driver_fr = {
	.name = "GB frame relay",
	.free_bind = free_bind,
};

struct priv_bind {
	struct osmo_fd fd;
	char netif[IF_NAMESIZE];
	struct osmo_fr_link *link;
	int ifindex;
	bool if_running;
};

struct priv_vc {
	struct osmo_sockaddr remote;
	uint16_t dlci;
	struct osmo_fr_dlc *dlc;
};

static void free_vc(struct gprs_ns2_vc *nsvc)
{
	OSMO_ASSERT(nsvc);

	if (!nsvc->priv)
		return;

	talloc_free(nsvc->priv);
	nsvc->priv = NULL;
}

static void dump_vty(const struct gprs_ns2_vc_bind *bind, struct vty *vty, bool _stats)
{
	struct priv_bind *priv;
	struct gprs_ns2_vc *nsvc;
	struct osmo_fr_link *fr_link;

	if (!bind)
		return;

	priv = bind->priv;
	fr_link = priv->link;

	vty_out(vty, "FR bind: %s, role: %s, link: %s%s", priv->netif,
		osmo_fr_role_str(fr_link->role), priv->if_running ? "UP" : "DOWN", VTY_NEWLINE);

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vty_out(vty, "    NSVCI %05u: %s%s", nsvc->nsvci, gprs_ns2_ll_str(nsvc), VTY_NEWLINE);
	}

	priv = bind->priv;
}

/*! clean up all private driver state. Should be only called by gprs_ns2_free_bind() */
static void free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (!bind)
		return;

	priv = bind->priv;

	OSMO_ASSERT(llist_empty(&bind->nsvc));

	osmo_fr_link_free(priv->link);
	osmo_fd_close(&priv->fd);
	talloc_free(priv);
}

static struct priv_vc *fr_alloc_vc(struct gprs_ns2_vc_bind *bind,
				   struct gprs_ns2_vc *nsvc,
				   uint16_t dlci)
{
	struct priv_bind *privb = bind->priv;
	struct priv_vc *priv = talloc_zero(bind, struct priv_vc);
	if (!priv)
		return NULL;

	nsvc->priv = priv;
	priv->dlci = dlci;
	priv->dlc = osmo_fr_dlc_alloc(privb->link, dlci);
	if (!priv->dlc) {
		nsvc->priv = NULL;
		talloc_free(priv);
		return NULL;
	}

	priv->dlc->rx_cb_data = nsvc;
	priv->dlc->rx_cb = fr_dlci_rx_cb;

	return priv;
}

int gprs_ns2_find_vc_by_dlci(struct gprs_ns2_vc_bind *bind,
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

/* PDU from the network interface towards the fr layer (upwards) */
static int handle_netif_read(struct osmo_fd *bfd)
{
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct priv_bind *priv = bind->priv;
	struct msgb *msg = msgb_alloc(NS_ALLOC_SIZE, "Gb/NS/FR/GRE Rx");
	struct sockaddr_ll sll;
	socklen_t sll_len = sizeof(sll);
	int rc = 0;

	if (!msg)
		return -ENOMEM;

	rc = recvfrom(bfd->fd, msg->data, NS_ALLOC_SIZE, 0, (struct sockaddr *)&sll, &sll_len);
	if (rc < 0) {
		LOGP(DLNS, LOGL_ERROR, "recv error %s during NS-FR-GRE recv\n",
		     strerror(errno));
		goto out_err;
	} else if (rc == 0) {
		goto out_err;
	}

	/* ignore any packets that we might have received for a different interface, between
	 * the socket() and the bind() call */
	if (sll.sll_ifindex != priv->ifindex)
		goto out_err;

	msgb_put(msg, rc);
	msg->dst = priv->link;
	return osmo_fr_rx(msg);

out_err:
	msgb_free(msg);
	return rc;
}

/* PDU from the frame relay towards the NS-VC (upwards) */
static int fr_dlci_rx_cb(void *cb_data, struct msgb *msg)
{
	int rc;
	struct gprs_ns2_vc *nsvc = cb_data;

	rc = ns2_recv_vc(nsvc, msg);

	return rc;
}

static int handle_netif_write(struct osmo_fd *bfd)
{
	/* FIXME */
	return -EIO;
}

static int fr_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & OSMO_FD_READ)
		rc = handle_netif_read(bfd);
	if (what & OSMO_FD_WRITE)
		rc = handle_netif_write(bfd);

	return rc;
}

/*! determine if given bind is for FR-GRE encapsulation. */
int gprs_ns2_is_fr_bind(struct gprs_ns2_vc_bind *bind)
{
	return (bind->driver == &vc_driver_fr);
}

/* PDU from the NS-VC towards the frame relay layer (downwards) */
static int fr_vc_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	struct priv_vc *vcpriv = nsvc->priv;

	msg->dst = vcpriv->dlc;
	return osmo_fr_tx_dlc(msg);
}

/* PDU from the frame relay layer towards the network interface (downwards) */
int fr_tx_cb(void *data, struct msgb *msg)
{
	struct gprs_ns2_vc_bind *bind = data;
	struct priv_bind *priv = bind->priv;
	int rc;

	/* FIXME half writes */
	rc = write(priv->fd.fd, msg->data, msg->len);
	msgb_free(msg);

	return rc;
}

static int devname2ifindex(const char *ifname)
{
	struct ifreq ifr;
	int sk, rc;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sk < 0)
		return sk;


	memset(&ifr, 0, sizeof(ifr));
	OSMO_STRLCPY_ARRAY(ifr.ifr_name, ifname);

	rc = ioctl(sk, SIOCGIFINDEX, &ifr);
	close(sk);
	if (rc < 0)
		return rc;

	return ifr.ifr_ifindex;
}

static int open_socket(int ifindex)
{
	struct sockaddr_ll addr;
	int fd, rc;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifindex;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_HDLC));
	if (fd < 0) {
		LOGP(DLNS, LOGL_ERROR, "Can not create AF_PACKET socket. Are you root or have CAP_RAW_SOCKET?\n");
		return fd;
	}

	/* there's a race condition between the above syscall and the bind() call below,
	 * causing other packets to be received in between */

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		LOGP(DLNS, LOGL_ERROR, "Can not bind AF_PACKET socket to ifindex %d\n", ifindex);
		close(fd);
		return rc;
	}

	return fd;
}

#ifdef ENABLE_LIBMNL

#include <osmocom/core/mnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#ifndef ARPHRD_FRAD
#define ARPHRD_FRAD  770
#endif

/* validate the netlink attributes */
static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_MTU:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			return MNL_CB_ERROR;
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

/* find the bind for the netdev (if any) */
static struct gprs_ns2_vc_bind *bind4netdev(struct gprs_ns2_inst *nsi, const char *ifname)
{
	struct gprs_ns2_vc_bind *bind;

	llist_for_each_entry(bind, &nsi->binding, list) {
		struct priv_bind *bpriv = bind->priv;
		if (!strcmp(bpriv->netif, ifname))
			return bind;
	}

	return NULL;
}

/* handle a single netlink message received via libmnl */
static int linkmon_mnl_cb(const struct nlmsghdr *nlh, void *data)
{
	struct osmo_mnl *omnl = data;
	struct gprs_ns2_vc_bind *bind;
	struct nlattr *tb[IFLA_MAX+1] = {};
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
	struct gprs_ns2_inst *nsi;
	const char *ifname;
	bool if_running;

	OSMO_ASSERT(omnl);
	OSMO_ASSERT(ifm);

	nsi = omnl->priv;

	if (ifm->ifi_type != ARPHRD_FRAD)
		return MNL_CB_OK;

	mnl_attr_parse(nlh, sizeof(*ifm), data_attr_cb, tb);

	if (!tb[IFLA_IFNAME])
		return MNL_CB_OK;
	ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
	if_running = !!(ifm->ifi_flags & IFF_RUNNING);

	bind = bind4netdev(nsi, ifname);
	if (bind) {
		struct priv_bind *bpriv = bind->priv;
		if (bpriv->if_running != if_running) {
			/* update running state */
			LOGP(DLNS, LOGL_NOTICE, "FR net-device '%s': Physical link state changed: %s\n",
			     ifname, if_running ? "UP" : "DOWN");
			bpriv->if_running = if_running;
		}
	}

	return MNL_CB_OK;
}

/* trigger one initial dump of all link information */
static void linkmon_initial_dump(struct osmo_mnl *omnl)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct rtgenmsg *rt;

	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = time(NULL);
	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = AF_PACKET;

	if (mnl_socket_sendto(omnl->mnls, nlh, nlh->nlmsg_len) < 0) {
		LOGP(DLNS, LOGL_ERROR, "linkmon: Cannot send rtnetlink message: %s\n", strerror(errno));
	}

	/* the response[s] will be handled just like the events */
}
#endif /* LIBMNL */


/*! Create a new bind for NS over FR.
 *  \param[in] nsi NS instance in which to create the bind
 *  \param[in] netif Network interface to bind to
 *  \param[in] fr_network
 *  \param[in] fr_role
 *  \param[out] result pointer to created bind
 *  \return 0 on success; negative on error */
int gprs_ns2_fr_bind(struct gprs_ns2_inst *nsi,
		     const char *name,
		     const char *netif,
		     struct osmo_fr_network *fr_network,
		     enum osmo_fr_role fr_role,
		     struct gprs_ns2_vc_bind **result)
{
	struct gprs_ns2_vc_bind *bind;
	struct priv_bind *priv;
	struct osmo_fr_link *fr_link;
	int rc = 0;

	if (!name)
		return -EINVAL;

	if (gprs_ns2_bind_by_name(nsi, name))
		return -EALREADY;

	bind = talloc_zero(nsi, struct gprs_ns2_vc_bind);
	if (!bind)
		return -ENOSPC;

	bind->name = talloc_strdup(bind, name);
	if (!bind->name) {
		rc = -ENOSPC;
		goto err_bind;
	}

	bind->driver = &vc_driver_fr;
	bind->ll = GPRS_NS2_LL_FR;
	bind->send_vc = fr_vc_sendmsg;
	bind->free_vc = free_vc;
	bind->dump_vty = dump_vty;
	bind->nsi = nsi;
	priv = bind->priv = talloc_zero(bind, struct priv_bind);
	if (!priv) {
		rc = -ENOSPC;
		goto err_name;
	}

	priv->fd.cb = fr_fd_cb;
	priv->fd.data = bind;
	if (strlen(netif) > IF_NAMESIZE) {
		rc = -EINVAL;
		goto err_priv;
	}
	strncpy(priv->netif, netif, sizeof(priv->netif));

	if (result)
		*result = bind;

	/* FIXME: move fd handling into socket.c */
	fr_link = osmo_fr_link_alloc(fr_network, fr_role, netif);
	if (!fr_link) {
		rc = -EINVAL;
		goto err_priv;
	}

	fr_link->tx_cb = fr_tx_cb;
	fr_link->tx_cb_data = bind;
	priv->link = fr_link;

	priv->ifindex = rc = devname2ifindex(netif);
	if (rc < 0) {
		LOGP(DLNS, LOGL_ERROR, "Can not get interface index for interface %s\n", netif);
		goto err_fr;
	}

	priv->fd.fd = rc = open_socket(priv->ifindex);
	if (rc < 0)
		goto err_fr;

	priv->fd.when = OSMO_FD_READ;
	rc = osmo_fd_register(&priv->fd);
	if (rc < 0)
		goto err_fd;

	INIT_LLIST_HEAD(&bind->nsvc);
	llist_add(&bind->list, &nsi->binding);

#ifdef ENABLE_LIBMNL
	if (!nsi->linkmon_mnl)
		nsi->linkmon_mnl = osmo_mnl_init(nsi, NETLINK_ROUTE, RTMGRP_LINK, linkmon_mnl_cb, nsi);

	/* we get a new full dump after every bind. which is a bit excessive. But that's just once
	 * at start-up, so we can get away with it */
	if (nsi->linkmon_mnl)
		linkmon_initial_dump(nsi->linkmon_mnl);
#endif

	return rc;

err_fd:
	close(priv->fd.fd);
err_fr:
	osmo_fr_link_free(fr_link);
err_priv:
	talloc_free(priv);
err_name:
	talloc_free((char *)bind->name);
err_bind:
	talloc_free(bind);

	return rc;
}

/*! Return the frame relay role of a bind
 * \param[in] bind The bind
 * \return the frame relay role or -EINVAL if bind is not frame relay
 */
enum osmo_fr_role gprs_ns2_fr_bind_role(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (bind->driver != &vc_driver_fr)
		return -EINVAL;

	priv = bind->priv;
	return priv->link->role;
}

/*! Return the network interface of the bind
 * \param[in] bind The bind
 * \return the network interface
 */
const char *gprs_ns2_fr_bind_netif(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (bind->driver != &vc_driver_fr)
		return NULL;

	priv = bind->priv;
	return priv->netif;
}

/*! Find NS bind for a given network interface
 * \param[in] nsi NS instance
 * \param[in] netif the network interface to search for
 * \return the bind or NULL if not found
 */
struct gprs_ns2_vc_bind *gprs_ns2_fr_bind_by_netif(
		struct gprs_ns2_inst *nsi,
		const char *netif)
{
	struct gprs_ns2_vc_bind *bind;
	const char *_netif;

	OSMO_ASSERT(nsi);
	OSMO_ASSERT(netif);

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!gprs_ns2_is_fr_bind(bind))
			continue;

		_netif = gprs_ns2_fr_bind_netif(bind);
		if (!strncmp(_netif, netif, IF_NAMESIZE))
			return bind;
	}

	return NULL;
}

/*! Create, connect and activate a new FR-based NS-VC
 *  \param[in] bind bind in which the new NS-VC is to be created
 *  \param[in] nsei NSEI of the NS Entity in which the NS-VC is to be created
 *  \param[in] dlci Data Link connection identifier
 *  \return pointer to newly-allocated, connected and activated NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_fr_connect(struct gprs_ns2_vc_bind *bind,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci,
					uint16_t dlci)
{
	struct gprs_ns2_vc *nsvc = NULL;
	struct priv_vc *priv = NULL;

	nsvc = gprs_ns2_fr_nsvc_by_dlci(bind, dlci);
	if (nsvc) {
		goto err;
	}

	nsvc = ns2_vc_alloc(bind, nse, true, NS2_VC_MODE_BLOCKRESET);
	if (!nsvc)
		goto err;

	nsvc->priv = priv = fr_alloc_vc(bind, nsvc, dlci);
	if (!priv)
		goto err;

	nsvc->nsvci = nsvci;
	nsvc->nsvci_is_valid = true;

	gprs_ns2_vc_fsm_start(nsvc);

	return nsvc;

err:
	gprs_ns2_free_nsvc(nsvc);
	return NULL;
}


/*! Create, connect and activate a new FR-based NS-VC
 *  \param[in] bind bind in which the new NS-VC is to be created
 *  \param[in] nsei NSEI of the NS Entity in which the NS-VC is to be created
 *  \param[in] dlci Data Link connection identifier
 *  \return pointer to newly-allocated, connected and activated NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_fr_connect2(struct gprs_ns2_vc_bind *bind,
					uint16_t nsei,
					uint16_t nsvci,
					uint16_t dlci)
{
	bool created_nse = false;
	struct gprs_ns2_vc *nsvc = NULL;
	struct priv_vc *priv = NULL;
	struct gprs_ns2_nse *nse = gprs_ns2_nse_by_nsei(bind->nsi, nsei);
	if (!nse) {
		nse = gprs_ns2_create_nse(bind->nsi, nsei, GPRS_NS2_LL_FR, NS2_DIALECT_STATIC_RESETBLOCK);
		if (!nse)
			return NULL;
		created_nse = true;
	}

	nsvc = gprs_ns2_fr_nsvc_by_dlci(bind, dlci);
	if (nsvc) {
		goto err_nse;
	}

	nsvc = ns2_vc_alloc(bind, nse, true, NS2_VC_MODE_BLOCKRESET);
	if (!nsvc)
		goto err_nse;

	nsvc->priv = priv = fr_alloc_vc(bind, nsvc, dlci);
	if (!priv)
		goto err;

	nsvc->nsvci = nsvci;
	nsvc->nsvci_is_valid = true;

	gprs_ns2_vc_fsm_start(nsvc);

	return nsvc;

err:
	gprs_ns2_free_nsvc(nsvc);
err_nse:
	if (created_nse)
		gprs_ns2_free_nse(nse);

	return NULL;
}

/*! Return the nsvc by dlci.
 * \param[in] bind
 * \param[in] dlci Data Link connection identifier
 * \return the nsvc or NULL if not found
 */
struct gprs_ns2_vc *gprs_ns2_fr_nsvc_by_dlci(struct gprs_ns2_vc_bind *bind,
					     uint16_t dlci)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vcpriv = nsvc->priv;

		if (dlci == vcpriv->dlci)
			return nsvc;
	}

	return NULL;
}

/*! Return the dlci of the nsvc
 * \param[in] nsvc
 * \return the dlci or 0 on error. 0 is not a valid dlci.
 */
uint16_t gprs_ns2_fr_nsvc_dlci(const struct gprs_ns2_vc *nsvc)
{
	struct priv_vc *vcpriv;

	if (!nsvc->bind)
		return 0;

	if (nsvc->bind->driver != &vc_driver_fr)
		return 0;

	vcpriv = nsvc->priv;
	return vcpriv->dlci;
}
