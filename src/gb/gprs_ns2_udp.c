/*! \file gprs_ns2_udp.c
 * NS-over-UDP implementation.
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2020 sysmocom - s.f.m.c. GmbH
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

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/select.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/socket.h>
#include <osmocom/gprs/gprs_ns2.h>

#include "common_vty.h"
#include "gprs_ns2_internal.h"


static void free_bind(struct gprs_ns2_vc_bind *bind);


struct gprs_ns2_vc_driver vc_driver_ip = {
	.name = "GB UDP IPv4/IPv6",
	.free_bind = free_bind,
};

struct priv_bind {
	struct osmo_io_fd *iofd;
	struct osmo_sockaddr addr;
	int dscp;
	uint8_t priority;
};

struct priv_vc {
	struct osmo_sockaddr remote;
};

/*! clean up all private driver state. Should be only called by gprs_ns2_free_bind() */
static void free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (!bind)
		return;

	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));

	priv = bind->priv;

	osmo_iofd_free(priv->iofd);
	priv->iofd = NULL;
	talloc_free(priv);
}

static void free_vc(struct gprs_ns2_vc *nsvc)
{
	if (!nsvc)
		return;

	if (!nsvc->priv)
		return;

	OSMO_ASSERT(gprs_ns2_is_ip_bind(nsvc->bind));
	talloc_free(nsvc->priv);
	nsvc->priv = NULL;
}

static void dump_vty(const struct gprs_ns2_vc_bind *bind,
		     struct vty *vty, bool stats)
{
	struct priv_bind *priv;
	struct gprs_ns2_vc *nsvc;
	struct osmo_sockaddr_str sockstr = {};
	unsigned long nsvcs = 0;

	if (!bind)
		return;

	priv = bind->priv;
	if (osmo_sockaddr_str_from_sockaddr(&sockstr, &priv->addr.u.sas))
		strcpy(sockstr.ip, "invalid");

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		nsvcs++;
	}

	vty_out(vty, "UDP bind: %s:%d DSCP: %d Priority: %u%s", sockstr.ip, sockstr.port,
		priv->dscp, priv->priority, VTY_NEWLINE);
	vty_out(vty, "  IP-SNS signalling weight: %u data weight: %u%s",
		bind->sns_sig_weight, bind->sns_data_weight, VTY_NEWLINE);
	vty_out(vty, "  %lu NS-VC:%s", nsvcs, VTY_NEWLINE);

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		ns2_vty_dump_nsvc(vty, nsvc, stats);
	}
}


/*! Find a NS-VC by its remote socket address.
 *  \param[in] bind in which to search
 *  \param[in] rem_addr remote peer socket address to search
 *  \returns NS-VC matching sockaddr; NULL if none found */
struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_bind(struct gprs_ns2_vc_bind *bind,
						   const struct osmo_sockaddr *rem_addr)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vcpriv = nsvc->priv;
		if (vcpriv->remote.u.sa.sa_family != rem_addr->u.sa.sa_family)
			continue;
		if (osmo_sockaddr_cmp(&vcpriv->remote, rem_addr))
			continue;

		return nsvc;
	}

	return NULL;
}

static inline int nsip_sendmsg(struct gprs_ns2_vc_bind *bind,
			       struct msgb *msg,
			       const struct osmo_sockaddr *dest)
{
	struct priv_bind *priv = bind->priv;

	return osmo_iofd_sendto_msgb(priv->iofd, msg, 0, dest);
}

/*! send the msg and free it afterwards.
 * \param nsvc NS-VC on which the message shall be sent
 * \param msg message to be sent
 * \return number of bytes transmitted; negative on error */
static int nsip_vc_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	int rc;
	struct gprs_ns2_vc_bind *bind = nsvc->bind;
	struct priv_vc *priv = nsvc->priv;

	rc = nsip_sendmsg(bind, msg, &priv->remote);

	return rc;
}

static struct priv_vc *ns2_driver_alloc_vc(struct gprs_ns2_vc_bind *bind, struct gprs_ns2_vc *nsvc, const struct osmo_sockaddr *remote)
{
	struct priv_vc *priv = talloc_zero(bind, struct priv_vc);
	if (!priv)
		return NULL;

	nsvc->priv = priv;
	priv->remote = *remote;

	return priv;
}

static void handle_nsip_recvfrom(struct osmo_io_fd *iofd, int error, struct msgb *msg,
				 const struct osmo_sockaddr *saddr)
{
	int rc = 0;
	struct gprs_ns2_vc_bind *bind = osmo_iofd_get_data(iofd);
	struct gprs_ns2_vc *nsvc;

	struct msgb *reject;

	msg->l2h = msgb_data(msg);

	/* check if a vc is available */
	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, saddr);
	if (!nsvc) {
		/* VC not found */
		rc = ns2_create_vc(bind, msg, saddr, "newconnection", &reject, &nsvc);
		switch (rc) {
		case NS2_CS_FOUND:
			break;
		case NS2_CS_ERROR:
		case NS2_CS_SKIPPED:
			rc = 0;
			goto out;
		case NS2_CS_REJECTED:
			/* nsip_sendmsg will free reject */
			rc = nsip_sendmsg(bind, reject, saddr);
			goto out;
		case NS2_CS_CREATED:
			ns2_driver_alloc_vc(bind, nsvc, saddr);
			/* only start the fsm for non SNS. SNS will take care of its own */
			if (nsvc->nse->dialect != GPRS_NS2_DIALECT_SNS)
				ns2_vc_fsm_start(nsvc);
			break;
		}
	}

	ns2_recv_vc(nsvc, msg);
	return;

out:
	msgb_free(msg);
}

static void handle_nsip_sendto(struct osmo_io_fd *iofd, int res,
			       struct msgb *msg,
			       const struct osmo_sockaddr *daddr)
{
	struct gprs_ns2_vc_bind *bind = osmo_iofd_get_data(iofd);
	struct gprs_ns2_vc *nsvc;

	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, daddr);
	if (!nsvc)
		return;

	if (OSMO_LIKELY(res >= 0)) {
		RATE_CTR_INC_NS(nsvc, NS_CTR_PKTS_OUT);
		RATE_CTR_ADD_NS(nsvc, NS_CTR_BYTES_OUT, res);
	} else {
		RATE_CTR_INC_NS(nsvc, NS_CTR_PKTS_OUT_DROP);
		RATE_CTR_ADD_NS(nsvc, NS_CTR_BYTES_OUT_DROP, msgb_length(msg));
	}
}

/*! Find NS bind for a given socket address
 *  \param[in] nsi NS instance
 *  \param[in] sockaddr socket address to search for
 *  \return
 */
struct gprs_ns2_vc_bind *gprs_ns2_ip_bind_by_sockaddr(struct gprs_ns2_inst *nsi,
						      const struct osmo_sockaddr *sockaddr)
{
	struct gprs_ns2_vc_bind *bind;
	const struct osmo_sockaddr *local;

	OSMO_ASSERT(nsi);
	OSMO_ASSERT(sockaddr);

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!gprs_ns2_is_ip_bind(bind))
			continue;

		local = gprs_ns2_ip_bind_sockaddr(bind);
		if (!osmo_sockaddr_cmp(sockaddr, local))
			return bind;
	}

	return NULL;
}

/*! Bind to an IPv4/IPv6 address
 *  \param[in] nsi NS Instance in which to create the NSVC
 *  \param[in] local the local address to bind to
 *  \param[in] dscp the DSCP/TOS bits used for transmitted data
 *  \param[out] result pointer to the created bind or if a bind with the name exists return the bind.
 *  \return 0 on success; negative on error. -EALREADY returned in case a bind with the name exists */
int gprs_ns2_ip_bind(struct gprs_ns2_inst *nsi,
		     const char *name,
		     const struct osmo_sockaddr *local,
		     int dscp,
		     struct gprs_ns2_vc_bind **result)
{
	struct gprs_ns2_vc_bind *bind;
	struct priv_bind *priv;
	int rc;

	struct osmo_io_ops ioops = {
		.sendto_cb = &handle_nsip_sendto,
		.recvfrom_cb = &handle_nsip_recvfrom,
	};

	if (local->u.sa.sa_family != AF_INET && local->u.sa.sa_family != AF_INET6)
		return -EINVAL;

	if (dscp < 0 || dscp > 63)
		return -EINVAL;

	bind = gprs_ns2_ip_bind_by_sockaddr(nsi, local);
	if (bind) {
		if (result)
			*result = bind;
		return -EBUSY;
	}

	rc = ns2_bind_alloc(nsi, name, &bind);
	if (rc < 0)
		return rc;

	bind->driver = &vc_driver_ip;
	bind->ll = GPRS_NS2_LL_UDP;
	/* expect 100 mbit at least.
	 * TODO: ask the network layer about the speed. But would require
	 * notification on change. */
	bind->transfer_capability = 100;
	bind->send_vc = nsip_vc_sendmsg;
	bind->free_vc = free_vc;
	bind->dump_vty = dump_vty;

	priv = bind->priv = talloc_zero(bind, struct priv_bind);
	if (!priv) {
		gprs_ns2_free_bind(bind);
		return -ENOMEM;
	}

	priv->addr = *local;
	priv->dscp = dscp;

	rc = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP,
				 local, NULL,
				 OSMO_SOCK_F_BIND | OSMO_SOCK_F_DSCP(priv->dscp));
	if (rc < 0) {
		gprs_ns2_free_bind(bind);
		return rc;
	}

	priv->iofd = osmo_iofd_setup(bind, rc, "NS bind", OSMO_IO_FD_MODE_RECVFROM_SENDTO, &ioops, bind);
	osmo_iofd_register(priv->iofd, rc);
	osmo_iofd_set_alloc_info(priv->iofd, 4096, 128);

	osmo_iofd_read_enable(priv->iofd);
	osmo_iofd_write_enable(priv->iofd);

	/* IPv4: max fragmented payload can be (13 bit) * 8 byte => 65535.
	 * IPv6: max payload can be 65535 (RFC 2460).
	 * UDP header = 8 byte */
	bind->mtu = 65535 - 8;
	if (result)
		*result = bind;

	return 0;
}

/*! Create new NS-VC to a given remote address
 *  \param[in] bind the bind we want to connect
 *  \param[in] nse NS entity to be used for the new NS-VC
 *  \param[in] remote remote address to connect to
 *  \return pointer to newly-allocated and connected NS-VC; NULL on error */
struct gprs_ns2_vc *ns2_ip_bind_connect(struct gprs_ns2_vc_bind *bind,
					struct gprs_ns2_nse *nse,
					const struct osmo_sockaddr *remote)
{
	struct gprs_ns2_vc *nsvc;
	const struct osmo_sockaddr *local;
	struct priv_vc *priv;
	enum gprs_ns2_vc_mode vc_mode;
	char idbuf[256], tmp[INET6_ADDRSTRLEN + 8];

	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));

	vc_mode = ns2_dialect_to_vc_mode(nse->dialect);
	if ((int) vc_mode == -1) {
		LOGNSE(nse, LOGL_ERROR, "Can not derive vc mode from dialect %d. Maybe libosmocore is too old.\n",
			nse->dialect);
		return NULL;
	}

	/* duplicate */
	if (gprs_ns2_nsvc_by_sockaddr_bind(bind, remote))
		return NULL;

	local = gprs_ns2_ip_bind_sockaddr(bind);
	osmo_sockaddr_to_str_buf(tmp, sizeof(tmp), local);
	snprintf(idbuf, sizeof(idbuf), "NSE%05u-NSVC-%s-%s-%s", nse->nsei, gprs_ns2_lltype_str(nse->ll),
		 tmp, osmo_sockaddr_to_str(remote));
	osmo_identifier_sanitize_buf(idbuf, NULL, '_');

	nsvc = ns2_vc_alloc(bind, nse, true, vc_mode, idbuf);
	if (!nsvc)
		return NULL;

	nsvc->priv = talloc_zero(bind, struct priv_vc);
	if (!nsvc->priv) {
		gprs_ns2_free_nsvc(nsvc);
		return NULL;
	}

	priv = nsvc->priv;
	priv->remote = *remote;

	return nsvc;
}

/*! Return the socket address of the local peer of a NS-VC.
 *  \param[in] nsvc NS-VC whose local peer we want to know
 *  \return address of the local peer; NULL in case of error */
const struct osmo_sockaddr *gprs_ns2_ip_vc_local(const struct gprs_ns2_vc *nsvc)
{
	struct priv_bind *priv;

	if (nsvc->bind->driver != &vc_driver_ip)
		return NULL;

	priv = nsvc->bind->priv;
	return &priv->addr;
}

/*! Return the socket address of the remote peer of a NS-VC.
 *  \param[in] nsvc NS-VC whose remote peer we want to know
 *  \return address of the remote peer; NULL in case of error */
const struct osmo_sockaddr *gprs_ns2_ip_vc_remote(const struct gprs_ns2_vc *nsvc)
{
	struct priv_vc *priv;

	if (nsvc->bind->driver != &vc_driver_ip)
		return NULL;

	priv = nsvc->priv;
	return &priv->remote;
}

/*! Compare the NS-VC with the given parameter
 *  \param[in] nsvc NS-VC to compare with
 *  \param[in] local The local address
 *  \param[in] remote The remote address
 *  \param[in] nsvci NS-VCI will only be used if the NS-VC in BLOCKRESET mode otherwise NS-VCI isn't applicable.
 *  \return true if the NS-VC has the same properties as given
 */
bool gprs_ns2_ip_vc_equal(const struct gprs_ns2_vc *nsvc,
			  const struct osmo_sockaddr *local,
			  const struct osmo_sockaddr *remote,
			  uint16_t nsvci)
{
	struct priv_vc *vpriv;
	struct priv_bind *bpriv;

	if (nsvc->bind->driver != &vc_driver_ip)
		return false;

	vpriv = nsvc->priv;
	bpriv = nsvc->bind->priv;

	if (osmo_sockaddr_cmp(local, &bpriv->addr))
		return false;

	if (osmo_sockaddr_cmp(remote, &vpriv->remote))
		return false;

	if (nsvc->mode == GPRS_NS2_VC_MODE_BLOCKRESET)
		if (nsvc->nsvci != nsvci)
			return false;

	return true;
}

/*! Return the locally bound socket address of the bind.
 *  \param[in] bind The bind whose local address we want to know
 *  \return address of the local bind */
const struct osmo_sockaddr *gprs_ns2_ip_bind_sockaddr(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;
	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));

	priv = bind->priv;
	return &priv->addr;
}

/*! Is the given bind an IP bind? */
int gprs_ns2_is_ip_bind(struct gprs_ns2_vc_bind *bind)
{
	return (bind->driver == &vc_driver_ip);
}

/*! Set the DSCP (TOS) bit value of the given bind. */
int gprs_ns2_ip_bind_set_dscp(struct gprs_ns2_vc_bind *bind, int dscp)
{
	struct priv_bind *priv;
	int rc = 0;

	if (dscp < 0 || dscp > 63)
		return -EINVAL;

	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));
	priv = bind->priv;

	if (dscp != priv->dscp) {
		priv->dscp = dscp;

		rc = osmo_sock_set_dscp(osmo_iofd_get_fd(priv->iofd), dscp);
		if (rc < 0) {
			LOGBIND(bind, LOGL_ERROR, "Failed to set the DSCP to %u with ret(%d) errno(%d)\n",
				dscp, rc, errno);
		}
	}

	return rc;
}

/*! Set the socket priority of the given bind. */
int gprs_ns2_ip_bind_set_priority(struct gprs_ns2_vc_bind *bind, uint8_t priority)
{
	struct priv_bind *priv;
	int rc = 0;

	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));
	priv = bind->priv;

	if (priority != priv->priority) {
		priv->priority = priority;

		rc = osmo_sock_set_priority(osmo_iofd_get_fd(priv->iofd), priority);
		if (rc < 0) {
			LOGBIND(bind, LOGL_ERROR, "Failed to set the priority to %u with ret(%d) errno(%d)\n",
				priority, rc, errno);
		}
	}

	return rc;
}


/*! Count UDP binds compatible with remote */
int ns2_ip_count_bind(struct gprs_ns2_inst *nsi, struct osmo_sockaddr *remote)
{
	struct gprs_ns2_vc_bind *bind;
	const struct osmo_sockaddr *sa;
	int count = 0;

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!gprs_ns2_is_ip_bind(bind))
			continue;

		sa = gprs_ns2_ip_bind_sockaddr(bind);
		if (!sa)
			continue;

		if (sa->u.sa.sa_family == remote->u.sa.sa_family)
			count++;
	}

	return count;
}

/* return the matching bind by index */
struct gprs_ns2_vc_bind *ns2_ip_get_bind_by_index(struct gprs_ns2_inst *nsi,
						  struct osmo_sockaddr *remote,
						  int index)
{
	struct gprs_ns2_vc_bind *bind;
	const struct osmo_sockaddr *sa;
	int i = 0;

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!gprs_ns2_is_ip_bind(bind))
			continue;

		sa = gprs_ns2_ip_bind_sockaddr(bind);
		if (!sa)
			continue;

		if (sa->u.sa.sa_family == remote->u.sa.sa_family) {
			if (index == i)
				return bind;
			i++;
		}
	}

	return NULL;
}

/*! set the signalling and data weight for this bind
 * \param[in] bind
 * \param[in] signalling the signalling weight
 * \param[in] data the data weight
 */
void gprs_ns2_ip_bind_set_sns_weight(struct gprs_ns2_vc_bind *bind, uint8_t signalling, uint8_t data)
{
	OSMO_ASSERT(gprs_ns2_is_ip_bind(bind));
	bind->sns_sig_weight = signalling;
	bind->sns_data_weight = data;
	ns2_sns_update_weights(bind);
}
