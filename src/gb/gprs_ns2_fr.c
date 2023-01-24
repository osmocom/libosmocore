/*! \file gprs_ns2_fr.c
 * NS-over-FR-over-GRE implementation.
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2009-2021 by Harald Welte <laforge@gnumonks.org>
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
#include <linux/if.h>

#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/hdlc.h>
#include <linux/hdlc/ioctl.h>
#include <linux/sockios.h>

#include <osmocom/gprs/frame_relay.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/core/netdev.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>
#include <osmocom/gprs/protocol/gsm_08_18.h>

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

#define E1_LINERATE 2048000
#define E1_SLOTS_TOTAL 32
#define E1_SLOTS_USED 31
/* usable bitrate of the E1 superchannel with 31 of 32 timeslots */
#define SUPERCHANNEL_LINERATE (E1_LINERATE*E1_SLOTS_USED)/E1_SLOTS_TOTAL
/* nanoseconds per bit (504) */
#define BIT_DURATION_NS (1000000000 / SUPERCHANNEL_LINERATE)

static void free_bind(struct gprs_ns2_vc_bind *bind);
static int fr_dlci_rx_cb(void *cb_data, struct msgb *msg);

struct gprs_ns2_vc_driver vc_driver_fr = {
	.name = "GB frame relay",
	.free_bind = free_bind,
};

struct priv_bind {
	struct osmo_netdev *netdev;
	char netif[IFNAMSIZ];
	struct osmo_fr_link *link;
	int ifindex;
	bool if_running;
	/* backlog queue for AF_PACKET / ENOBUFS handling (see OS#4995) */
	struct {
		/* file-descriptor for AF_PACKET socket */
		struct osmo_fd ofd;
		/* LMI bucket (we only store the last LMI message, no need to queue */
		struct msgb *lmi_msg;
		/* list of NS msgb (backlog) */
		struct llist_head list;
		/* timer to trigger next attempt of AF_PACKET write */
		struct osmo_timer_list timer;
		/* re-try after that many micro-seconds */
		uint32_t retry_us;
	} backlog;
};

struct priv_vc {
	struct osmo_sockaddr remote;
	uint16_t dlci;
	struct osmo_fr_dlc *dlc;
};

static void free_vc(struct gprs_ns2_vc *nsvc)
{
	if (!nsvc)
		return;

	if (!nsvc->priv)
		return;

	OSMO_ASSERT(gprs_ns2_is_fr_bind(nsvc->bind));
	talloc_free(nsvc->priv);
	nsvc->priv = NULL;
}

static void dump_vty(const struct gprs_ns2_vc_bind *bind, struct vty *vty, bool stats)
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
		ns2_vty_dump_nsvc(vty, nsvc, stats);
	}

	priv = bind->priv;
}

/*! clean up all private driver state. Should be only called by gprs_ns2_free_bind() */
static void free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;
	struct msgb *msg, *msg2;

	if (!bind)
		return;

	OSMO_ASSERT(gprs_ns2_is_fr_bind(bind));
	priv = bind->priv;

	OSMO_ASSERT(llist_empty(&bind->nsvc));

	osmo_timer_del(&priv->backlog.timer);
	llist_for_each_entry_safe(msg, msg2, &priv->backlog.list, list) {
		msgb_free(msg);
	}
	msgb_free(priv->backlog.lmi_msg);

	osmo_netdev_free(priv->netdev);
	osmo_fr_link_free(priv->link);
	osmo_fd_close(&priv->backlog.ofd);
	talloc_free(priv);
}

static void fr_dlci_status_cb(struct osmo_fr_dlc *dlc, void *cb_data, bool active)
{
	struct gprs_ns2_vc *nsvc = cb_data;

	if (active) {
		ns2_vc_fsm_start(nsvc);
	} else {
		ns2_vc_force_unconfigured(nsvc);
	}
}

static struct priv_vc *fr_alloc_vc(struct gprs_ns2_vc_bind *bind,
				   struct gprs_ns2_vc *nsvc,
				   uint16_t dlci)
{
	struct priv_bind *privb = bind->priv;
	struct priv_vc *priv = talloc_zero(bind, struct priv_vc);
	if (!priv)
		return NULL;

	OSMO_ASSERT(gprs_ns2_is_fr_bind(bind));
	nsvc->priv = priv;
	priv->dlci = dlci;
	priv->dlc = osmo_fr_dlc_alloc(privb->link, dlci);
	if (!priv->dlc) {
		nsvc->priv = NULL;
		talloc_free(priv);
		return NULL;
	}

	priv->dlc->cb_data = nsvc;
	priv->dlc->rx_cb = fr_dlci_rx_cb;
	priv->dlc->status_cb = fr_dlci_status_cb;

	return priv;
}

int gprs_ns2_find_vc_by_dlci(struct gprs_ns2_vc_bind *bind,
			     uint16_t dlci,
			     struct gprs_ns2_vc **result)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	OSMO_ASSERT(gprs_ns2_is_fr_bind(bind));
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
static int fr_netif_ofd_cb(struct osmo_fd *bfd, uint32_t what)
{
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct priv_bind *priv = bind->priv;
	struct msgb *msg;
	struct sockaddr_ll sll;
	socklen_t sll_len = sizeof(sll);
	int rc = 0;

	/* we only handle read here. write to AF_PACKET sockets cannot be triggered
	 * by select or poll, see OS#4995 */
	if (!(what & OSMO_FD_READ))
		return 0;

	msg = msgb_alloc(NS_ALLOC_SIZE, "Gb/NS/FR Rx");
	if (!msg)
		return -ENOMEM;

	rc = recvfrom(bfd->fd, msg->data, NS_ALLOC_SIZE, 0, (struct sockaddr *)&sll, &sll_len);
	if (rc < 0) {
		LOGBIND(bind, LOGL_ERROR, "recv error %s during NS-FR recv\n", strerror(errno));
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

static int fr_netif_write_one(struct gprs_ns2_vc_bind *bind, struct msgb *msg)
{
	struct priv_bind *priv = bind->priv;
	unsigned int len = msgb_length(msg);
	int rc;

	/* estimate the retry time based on the data rate it takes to transmit */
	priv->backlog.retry_us = (BIT_DURATION_NS * 8 * len) / 1000;

	rc = write(priv->backlog.ofd.fd, msgb_data(msg), len);
	if (rc == len) {
		msgb_free(msg);
		return 0;
	} else if (rc < 0) {
		/* don't free, the caller might want to re-transmit */
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			/* not a real error, but more a normal event on AF_PACKET */
			/* don't free the message and let the caller re-enqueue */
			return -errno;
		default:
			/* an actual error, like -ENETDOWN, -EMSGSIZE */
			LOGBIND(bind, LOGL_ERROR, "error during write to AF_PACKET: %s\n", strerror(errno));
			msgb_free(msg);
			return 0;
		}
	} else {
		/* short write */
		LOGBIND(bind, LOGL_ERROR, "short write on AF_PACKET: %d < %d\n", rc, len);
		msgb_free(msg);
		return 0;
	}
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

static void enqueue_at_head(struct gprs_ns2_vc_bind *bind, struct msgb *msg)
{
	struct priv_bind *priv = bind->priv;
	llist_add(&msg->list, &priv->backlog.list);
	osmo_stat_item_inc(osmo_stat_item_group_get_item(bind->statg, NS2_BIND_STAT_BACKLOG_LEN), 1);
	osmo_timer_schedule(&priv->backlog.timer, 0, priv->backlog.retry_us);
}

static void enqueue_at_tail(struct gprs_ns2_vc_bind *bind, struct msgb *msg)
{
	struct priv_bind *priv = bind->priv;
	llist_add_tail(&msg->list, &priv->backlog.list);
	osmo_stat_item_inc(osmo_stat_item_group_get_item(bind->statg, NS2_BIND_STAT_BACKLOG_LEN), 1);
	osmo_timer_schedule(&priv->backlog.timer, 0, priv->backlog.retry_us);
}

#define LMI_Q933A_DLCI 0

/* enqueue to backlog (LMI, signaling) or drop (userdata msg) */
static int backlog_enqueue_or_free(struct gprs_ns2_vc_bind *bind, struct msgb *msg)
{
	struct priv_bind *priv = bind->priv;
	uint8_t dlci = msg->data[0];
	uint8_t ns_pdu_type;
	uint16_t bvci;

	if (msgb_length(msg) < 1)
		goto out_free;

	/* we want to enqueue only Q.933 LMI traffic or NS signaling; NOT user traffic */
	switch (dlci) {
	case LMI_Q933A_DLCI:
		/* always store only the last LMI message in the lmi_msg bucket */
		msgb_free(priv->backlog.lmi_msg);
		priv->backlog.lmi_msg = msg;
		return 0;
	default:
		/* there's no point in trying to enqueue messages if the interface is down */
		if (!priv->if_running)
			break;

		if (msgb_length(msg) < 3)
			break;
		ns_pdu_type = msg->data[2];
		switch (ns_pdu_type) {
		case NS_PDUT_UNITDATA:
			if (msgb_length(msg) < 6)
				break;
			bvci = osmo_load16be(msg->data + 4);
			/* enqueue BVCI=0 traffic at tail of queue */
			if (bvci == BVCI_SIGNALLING) {
				enqueue_at_tail(bind, msg);
				return 0;
			}
			break;
		default:
			/* enqueue NS signaling traffic at head of queue */
			enqueue_at_head(bind, msg);
			return 0;
		}
		break;
	}

out_free:
	/* drop everything that is not LMI, NS-signaling or BVCI-0 */
	msgb_free(msg);
	return -1;
}

static void fr_backlog_timer_cb(void *data)
{
	struct gprs_ns2_vc_bind *bind = data;
	struct priv_bind *priv = bind->priv;
	int i, rc;

	/* first try to get rid of the LMI message, if any */
	if (priv->backlog.lmi_msg) {
		rc = fr_netif_write_one(bind, priv->backlog.lmi_msg);
		if (rc < 0)
			goto restart_timer;
		/* fr_netif_write_one() has just free'd it */
		priv->backlog.lmi_msg = NULL;
	}

	/* attempt to send up to 10 messages in every timer */
	for (i = 0; i < 10; i++) {
		struct msgb *msg = msgb_dequeue(&priv->backlog.list);
		if (!msg)
			break;

		rc = fr_netif_write_one(bind, msg);
		if (rc < 0) {
			/* re-add at head of list */
			llist_add(&msg->list, &priv->backlog.list);
			break;
		}
		osmo_stat_item_dec(osmo_stat_item_group_get_item(bind->statg, NS2_BIND_STAT_BACKLOG_LEN), 1);
	}

restart_timer:
	/* re-start timer if we still have data in the queue */
	if (!llist_empty(&priv->backlog.list))
		osmo_timer_schedule(&priv->backlog.timer, 0, priv->backlog.retry_us);
}

/* PDU from the frame relay layer towards the network interface (downwards) */
int fr_tx_cb(void *data, struct msgb *msg)
{
	struct gprs_ns2_vc_bind *bind = data;
	struct priv_bind *priv = bind->priv;
	int rc;

	if (llist_empty(&priv->backlog.list)) {
		/* attempt to transmit right now */
		rc = fr_netif_write_one(bind, msg);
		if (rc < 0) {
			/* enqueue to backlog in case it fails */
			return backlog_enqueue_or_free(bind, msg);
		}
	} else {
		/* enqueue to backlog */
		return backlog_enqueue_or_free(bind, msg);
	}

	return 0;
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

static int open_socket(int ifindex, const struct gprs_ns2_vc_bind *nsbind)
{
	struct sockaddr_ll addr;
	int fd, rc;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifindex;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_HDLC));
	if (fd < 0) {
		LOGBIND(nsbind, LOGL_ERROR, "Can not create AF_PACKET socket. Are you root or have CAP_NET_RAW?\n");
		return fd;
	}

	/* there's a race condition between the above syscall and the bind() call below,
	 * causing other packets to be received in between */

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		LOGBIND(nsbind, LOGL_ERROR, "Can not bind AF_PACKET socket to ifindex %d\n", ifindex);
		close(fd);
		return rc;
	}

	return fd;
}

static int gprs_n2_fr_ifupdown_ind_cb(struct osmo_netdev *netdev, bool if_running)
{
	struct gprs_ns2_vc_bind *bind = osmo_netdev_get_priv_data(netdev);
	struct priv_bind *bpriv = bind->priv;
	struct msgb *msg, *msg2;

	if (bpriv->if_running == if_running)
		return 0;

	LOGBIND(bind, LOGL_NOTICE, "FR net-device '%s': Physical link state changed: %s\n",
		bpriv->netif, if_running ? "UP" : "DOWN");

	/* free any backlog, both on IFUP and IFDOWN. Keep the LMI, as it makes
	 * sense to get one out of the door ASAP. */
	llist_for_each_entry_safe(msg, msg2, &bpriv->backlog.list, list) {
		msgb_free(msg);
	}

	if (if_running) {
		/* interface just came up */
		if (bpriv->backlog.lmi_msg)
			osmo_timer_schedule(&bpriv->backlog.timer, 0, bpriv->backlog.retry_us);
	} else {
		/* interface just went down; no need to retransmit */
		osmo_timer_del(&bpriv->backlog.timer);
	}

	bpriv->if_running = if_running;
	return 0;
}

static int gprs_n2_fr_mtu_chg_cb(struct osmo_netdev *netdev, uint32_t new_mtu)
{
	struct gprs_ns2_vc_bind *bind = osmo_netdev_get_priv_data(netdev);
	struct priv_bind *bpriv = bind->priv;
	struct gprs_ns2_nse *nse;

	/* 2 byte DLCI header */
	if (new_mtu <= 2)
		return 0;
	new_mtu -= 2;

	if (new_mtu == bind->mtu)
		return 0;

	LOGBIND(bind, LOGL_INFO, "MTU changed from %d to %d.\n",
		bind->mtu + 2, new_mtu + 2);

	bind->mtu = new_mtu;
	if (!bpriv->if_running)
		return 0;

	llist_for_each_entry(nse, &bind->nsi->nse, list) {
		ns2_nse_update_mtu(nse);
	}
	return 0;
}

static int set_ifupdown(const char *netif, bool up)
{
	int sock, rc;
	struct ifreq req;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return sock;

	memset(&req, 0, sizeof req);
	OSMO_STRLCPY_ARRAY(req.ifr_name, netif);

	rc = ioctl(sock, SIOCGIFFLAGS, &req);
	if (rc < 0) {
		close(sock);
		return rc;
	}

	if ((req.ifr_flags & IFF_UP) == up) {
		close(sock);
		return 0;
	}

	if (up)
		req.ifr_flags |= IFF_UP;

	rc = ioctl(sock, SIOCSIFFLAGS, &req);
	close(sock);
	return rc;
}

static int setup_device(const char *netif, const struct gprs_ns2_vc_bind *bind)
{
	int sock, rc;
	char buffer[128];
	fr_proto *fr = (void*)buffer;
	struct ifreq req;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		LOGBIND(bind, LOGL_ERROR, "%s: Unable to create socket: %s\n",
			netif, strerror(errno));
		return sock;
	}

	memset(&req, 0, sizeof(struct ifreq));
	memset(&buffer, 0, sizeof(buffer));
	OSMO_STRLCPY_ARRAY(req.ifr_name, netif);
	req.ifr_settings.ifs_ifsu.sync = (void*)buffer;
	req.ifr_settings.size = sizeof(buffer);
	req.ifr_settings.type = IF_GET_PROTO;

	/* EINVAL is returned when no protocol has been set */
	rc = ioctl(sock, SIOCWANDEV, &req);
	if (rc < 0 && errno != EINVAL) {
		LOGBIND(bind, LOGL_ERROR, "%s: Unable to get FR protocol information: %s\n",
			netif, strerror(errno));
		goto err;
	}

	/* check if the device is good */
	if (rc == 0 && req.ifr_settings.type == IF_PROTO_FR && fr->lmi == LMI_NONE) {
		LOGBIND(bind, LOGL_NOTICE, "%s: has correct frame relay mode and lmi\n", netif);
		goto ifup;
	}

	/* modify the device to match */
	rc = set_ifupdown(netif, false);
	if (rc) {
		LOGBIND(bind, LOGL_ERROR, "Unable to bring down the device %s: %s\n",
			netif, strerror(errno));
		goto err;
	}

	memset(&req, 0, sizeof(struct ifreq));
	memset(fr, 0, sizeof(fr_proto));
	OSMO_STRLCPY_ARRAY(req.ifr_name, netif);
	req.ifr_settings.type = IF_PROTO_FR;
	req.ifr_settings.size = sizeof(fr_proto);
	req.ifr_settings.ifs_ifsu.fr = fr;
	fr->lmi = LMI_NONE;
	/* even those settings aren't used, they must be in the range */
	/* polling verification timer*/
	fr->t391 = 10;
	/* link integrity verification polling timer */
	fr->t392 = 15;
	/* full status polling counter*/
	fr->n391 = 6;
	/* error threshold */
	fr->n392 = 3;
	/* monitored events count */
	fr->n393 = 4;

	LOGBIND(bind, LOGL_INFO, "%s: Setting frame relay related parameters\n", netif);
	rc = ioctl(sock, SIOCWANDEV, &req);
	if (rc) {
		LOGBIND(bind, LOGL_ERROR, "%s: Unable to set FR protocol on information: %s\n",
			netif, strerror(errno));
		goto err;
	}

ifup:
	rc = set_ifupdown(netif, true);
	if (rc)
		LOGBIND(bind, LOGL_ERROR, "Unable to bring up the device %s: %s\n",
			netif, strerror(errno));
err:
	close(sock);
	return rc;
}

/*! Create a new bind for NS over FR.
 *  \param[in] nsi NS instance in which to create the bind
 *  \param[in] netif Network interface to bind to
 *  \param[in] fr_network
 *  \param[in] fr_role
 *  \param[out] result pointer to the created bind or if a bind with the name exists return the bind.
 *  \return 0 on success; negative on error. -EALREADY returned in case a bind with the name exists */
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

	if (strlen(netif) > IFNAMSIZ)
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

	bind->driver = &vc_driver_fr;
	bind->ll = GPRS_NS2_LL_FR;
	/* 2 mbit */
	bind->transfer_capability = 2;
	bind->send_vc = fr_vc_sendmsg;
	bind->free_vc = free_vc;
	bind->dump_vty = dump_vty;
	bind->mtu = FRAME_RELAY_SDU;
	priv = bind->priv = talloc_zero(bind, struct priv_bind);
	if (!priv) {
		rc = -ENOMEM;
		goto err_bind;
	}

	INIT_LLIST_HEAD(&priv->backlog.list);
	OSMO_STRLCPY_ARRAY(priv->netif, netif);

	/* FIXME: move fd handling into socket.c */
	fr_link = osmo_fr_link_alloc(fr_network, fr_role, netif);
	if (!fr_link) {
		rc = -EINVAL;
		goto err_bind;
	}

	fr_link->tx_cb = fr_tx_cb;
	fr_link->cb_data = bind;
	priv->link = fr_link;

	priv->ifindex = rc = devname2ifindex(netif);
	if (rc < 0) {
		LOGBIND(bind, LOGL_ERROR, "Can not get interface index for interface %s\n", netif);
		goto err_fr;
	}

	priv->netdev = osmo_netdev_alloc(bind, name);
	if (!priv->netdev) {
		rc = -ENOENT;
		goto err_fr;
	}
	osmo_netdev_set_priv_data(priv->netdev, bind);
	osmo_netdev_set_ifupdown_ind_cb(priv->netdev, gprs_n2_fr_ifupdown_ind_cb);
	osmo_netdev_set_mtu_chg_cb(priv->netdev, gprs_n2_fr_mtu_chg_cb);
	rc = osmo_netdev_set_ifindex(priv->netdev, priv->ifindex);
	if (rc < 0)
		goto err_free_netdev;
	rc = osmo_netdev_register(priv->netdev);
	if (rc < 0)
		goto err_free_netdev;

	/* set protocol frame relay and lmi */
	rc = setup_device(priv->netif, bind);
	if(rc < 0) {
		LOGBIND(bind, LOGL_ERROR, "Failed to setup the interface %s for frame relay and lmi\n", netif);
		goto err_free_netdev;
	}

	rc = open_socket(priv->ifindex, bind);
	if (rc < 0)
		goto err_free_netdev;
	priv->backlog.retry_us = 2500; /* start with some non-zero value; this corrsponds to 496 bytes */
	osmo_timer_setup(&priv->backlog.timer, fr_backlog_timer_cb, bind);
	osmo_fd_setup(&priv->backlog.ofd, rc, OSMO_FD_READ, fr_netif_ofd_cb, bind, 0);
	rc = osmo_fd_register(&priv->backlog.ofd);
	if (rc < 0)
		goto err_fd;

	if (result)
		*result = bind;

	return rc;

err_fd:
	close(priv->backlog.ofd.fd);
err_free_netdev:
	osmo_netdev_free(priv->netdev);
	priv->netdev = NULL;
err_fr:
	osmo_fr_link_free(fr_link);
	priv->link = NULL;
err_bind:
	gprs_ns2_free_bind(bind);

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
		if (!strncmp(_netif, netif, IFNAMSIZ))
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
	struct priv_bind *bpriv = bind->priv;
	char idbuf[64];

	OSMO_ASSERT(gprs_ns2_is_fr_bind(bind));
	nsvc = gprs_ns2_fr_nsvc_by_dlci(bind, dlci);
	if (nsvc) {
		goto err;
	}

	snprintf(idbuf, sizeof(idbuf), "NSE%05u-NSVC%05u-%s-%s-DLCI%u", nse->nsei, nsvci,
		 gprs_ns2_lltype_str(nse->ll), bpriv->netif, dlci);
	osmo_identifier_sanitize_buf(idbuf, NULL, '_');
	nsvc = ns2_vc_alloc(bind, nse, true, GPRS_NS2_VC_MODE_BLOCKRESET, idbuf);
	if (!nsvc)
		goto err;

	nsvc->priv = priv = fr_alloc_vc(bind, nsvc, dlci);
	if (!priv)
		goto err;

	nsvc->nsvci = nsvci;
	nsvc->nsvci_is_valid = true;

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
	struct gprs_ns2_nse *nse;

	OSMO_ASSERT(gprs_ns2_is_fr_bind(bind));
	nse = gprs_ns2_nse_by_nsei(bind->nsi, nsei);
	if (!nse) {
		nse = gprs_ns2_create_nse(bind->nsi, nsei, GPRS_NS2_LL_FR, GPRS_NS2_DIALECT_STATIC_RESETBLOCK);
		if (!nse)
			return NULL;
		created_nse = true;
	}

	nsvc = gprs_ns2_fr_connect(bind, nse, nsvci, dlci);
	if (!nsvc)
		goto err_nse;

	return nsvc;

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

	OSMO_ASSERT(gprs_ns2_is_fr_bind(bind));
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
