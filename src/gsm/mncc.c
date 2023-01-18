/* mncc.c - utility routines for the MNCC API between the 04.08
 *	    message parsing and the actual Call Control logic */

/* (C) 2008-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#ifdef HAVE_SYS_SOCKET_H

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/mncc.h>

/* FIXME FIXME FIXME FIXME FIXME START */
#define MNCC_SETUP_REQ		0x0101
#define MNCC_SETUP_IND		0x0102
#define MNCC_SETUP_RSP		0x0103
#define MNCC_SETUP_CNF		0x0104
#define MNCC_SETUP_COMPL_REQ	0x0105
#define MNCC_SETUP_COMPL_IND	0x0106
/* MNCC_REJ_* is perfomed via MNCC_REL_* */
#define MNCC_CALL_CONF_IND	0x0107
#define MNCC_CALL_PROC_REQ	0x0108
#define MNCC_PROGRESS_REQ	0x0109
#define MNCC_ALERT_REQ		0x010a
#define MNCC_ALERT_IND		0x010b
#define MNCC_NOTIFY_REQ		0x010c
#define MNCC_NOTIFY_IND		0x010d
#define MNCC_DISC_REQ		0x010e
#define MNCC_DISC_IND		0x010f
#define MNCC_REL_REQ		0x0110
#define MNCC_REL_IND		0x0111
#define MNCC_REL_CNF		0x0112
#define MNCC_FACILITY_REQ	0x0113
#define MNCC_FACILITY_IND	0x0114
#define MNCC_START_DTMF_IND	0x0115
#define MNCC_START_DTMF_RSP	0x0116
#define MNCC_START_DTMF_REJ	0x0117
#define MNCC_STOP_DTMF_IND	0x0118
#define MNCC_STOP_DTMF_RSP	0x0119
#define MNCC_MODIFY_REQ		0x011a
#define MNCC_MODIFY_IND		0x011b
#define MNCC_MODIFY_RSP		0x011c
#define MNCC_MODIFY_CNF		0x011d
#define MNCC_MODIFY_REJ		0x011e
#define MNCC_HOLD_IND		0x011f
#define MNCC_HOLD_CNF		0x0120
#define MNCC_HOLD_REJ		0x0121
#define MNCC_RETRIEVE_IND	0x0122
#define MNCC_RETRIEVE_CNF	0x0123
#define MNCC_RETRIEVE_REJ	0x0124
#define MNCC_USERINFO_REQ	0x0125
#define MNCC_USERINFO_IND	0x0126
#define MNCC_REJ_REQ		0x0127
#define MNCC_REJ_IND		0x0128

#define MNCC_BRIDGE		0x0200
#define MNCC_FRAME_RECV		0x0201
#define MNCC_FRAME_DROP		0x0202
#define MNCC_LCHAN_MODIFY	0x0203
#define MNCC_RTP_CREATE		0x0204
#define MNCC_RTP_CONNECT	0x0205
#define MNCC_RTP_FREE		0x0206

#define GSM_TCHF_FRAME		0x0300
#define GSM_TCHF_FRAME_EFR	0x0301
#define GSM_TCHH_FRAME		0x0302
#define GSM_TCH_FRAME_AMR	0x0303
#define GSM_BAD_FRAME		0x03ff

#define MNCC_SOCKET_HELLO	0x0400

#define GSM_MAX_FACILITY	128
#define GSM_MAX_SSVERSION	128
#define GSM_MAX_USERUSER	128

#define	MNCC_F_BEARER_CAP	0x0001
#define MNCC_F_CALLED		0x0002
#define MNCC_F_CALLING		0x0004
#define MNCC_F_REDIRECTING	0x0008
#define MNCC_F_CONNECTED	0x0010
#define MNCC_F_CAUSE		0x0020
#define MNCC_F_USERUSER		0x0040
#define MNCC_F_PROGRESS		0x0080
#define MNCC_F_EMERGENCY	0x0100
#define MNCC_F_FACILITY		0x0200
#define MNCC_F_SSVERSION	0x0400
#define MNCC_F_CCCAP		0x0800
#define MNCC_F_KEYPAD		0x1000
#define MNCC_F_SIGNAL		0x2000

struct gsm_mncc {
	/* context based information */
	uint32_t	msg_type;
	uint32_t	callref;

	/* which fields are present */
	uint32_t	fields;

	/* data derived informations (MNCC_F_ based) */
	struct gsm_mncc_bearer_cap	bearer_cap;
	struct gsm_mncc_number		called;
	struct gsm_mncc_number		calling;
	struct gsm_mncc_number		redirecting;
	struct gsm_mncc_number		connected;
	struct gsm_mncc_cause		cause;
	struct gsm_mncc_progress	progress;
	struct gsm_mncc_useruser	useruser;
	struct gsm_mncc_facility	facility;
	struct gsm_mncc_cccap		cccap;
	struct gsm_mncc_ssversion	ssversion;
	struct	{
		int		sup;
		int		inv;
	} clir;
	int		signal;

	/* data derived information, not MNCC_F based */
	int		keypad;
	int		more;
	int		notify; /* 0..127 */
	int		emergency;
	char		imsi[16];

	unsigned char	lchan_type;
	unsigned char	lchan_mode;
};

struct gsm_data_frame {
	uint32_t	msg_type;
	uint32_t	callref;
	unsigned char	data[0];
};

#define MNCC_SOCK_VERSION	5
struct gsm_mncc_hello {
	uint32_t	msg_type;
	uint32_t	version;

	/* send the sizes of the structs */
	uint32_t	mncc_size;
	uint32_t	data_frame_size;

	/* send some offsets */
	uint32_t	called_offset;
	uint32_t	signal_offset;
	uint32_t	emergency_offset;
	uint32_t	lchan_type_offset;
};

struct gsm_mncc_rtp {
	uint32_t	msg_type;
	uint32_t	callref;
	uint32_t	ip;
	uint16_t	port;
	uint32_t	payload_type;
	uint32_t	payload_msg_type;
};

struct gsm_mncc_bridge {
	uint32_t	msg_type;
	uint32_t	callref[2];
};

/* FIXME FIXME FIXME FIXME FIXME END */

const struct value_string osmo_mncc_names[] = {
	{ MNCC_SETUP_REQ, "MNCC_SETUP_REQ" },
	{ MNCC_SETUP_IND, "MNCC_SETUP_IND" },
	{ MNCC_SETUP_RSP, "MNCC_SETUP_RSP" },
	{ MNCC_SETUP_CNF, "MNCC_SETUP_CNF" },
	{ MNCC_SETUP_COMPL_REQ, "MNCC_SETUP_COMPL_REQ" },
	{ MNCC_SETUP_COMPL_IND, "MNCC_SETUP_COMPL_IND" },
	{ MNCC_CALL_CONF_IND, "MNCC_CALL_CONF_IND" },
	{ MNCC_CALL_PROC_REQ, "MNCC_CALL_PROC_REQ" },
	{ MNCC_PROGRESS_REQ, "MNCC_PROGRESS_REQ" },
	{ MNCC_ALERT_REQ, "MNCC_ALERT_REQ" },
	{ MNCC_ALERT_IND, "MNCC_ALERT_IND" },
	{ MNCC_NOTIFY_REQ, "MNCC_NOTIFY_REQ" },
	{ MNCC_NOTIFY_IND, "MNCC_NOTIFY_IND" },
	{ MNCC_DISC_REQ, "MNCC_DISC_REQ" },
	{ MNCC_DISC_IND, "MNCC_DISC_IND" },
	{ MNCC_REL_REQ, "MNCC_REL_REQ" },
	{ MNCC_REL_IND, "MNCC_REL_IND" },
	{ MNCC_REL_CNF, "MNCC_REL_CNF" },
	{ MNCC_FACILITY_REQ, "MNCC_FACILITY_REQ" },
	{ MNCC_FACILITY_IND, "MNCC_FACILITY_IND" },
	{ MNCC_START_DTMF_IND, "MNCC_START_DTMF_IND" },
	{ MNCC_START_DTMF_RSP, "MNCC_START_DTMF_RSP" },
	{ MNCC_START_DTMF_REJ, "MNCC_START_DTMF_REJ" },
	{ MNCC_STOP_DTMF_IND, "MNCC_STOP_DTMF_IND" },
	{ MNCC_STOP_DTMF_RSP, "MNCC_STOP_DTMF_RSP" },
	{ MNCC_MODIFY_REQ, "MNCC_MODIFY_REQ" },
	{ MNCC_MODIFY_IND, "MNCC_MODIFY_IND" },
	{ MNCC_MODIFY_RSP, "MNCC_MODIFY_RSP" },
	{ MNCC_MODIFY_CNF, "MNCC_MODIFY_CNF" },
	{ MNCC_MODIFY_REJ, "MNCC_MODIFY_REJ" },
	{ MNCC_HOLD_IND, "MNCC_HOLD_IND" },
	{ MNCC_HOLD_CNF, "MNCC_HOLD_CNF" },
	{ MNCC_HOLD_REJ, "MNCC_HOLD_REJ" },
	{ MNCC_RETRIEVE_IND, "MNCC_RETRIEVE_IND" },
	{ MNCC_RETRIEVE_CNF, "MNCC_RETRIEVE_CNF" },
	{ MNCC_RETRIEVE_REJ, "MNCC_RETRIEVE_REJ" },
	{ MNCC_USERINFO_REQ, "MNCC_USERINFO_REQ" },
	{ MNCC_USERINFO_IND, "MNCC_USERINFO_IND" },
	{ MNCC_REJ_REQ, "MNCC_REJ_REQ" },
	{ MNCC_REJ_IND, "MNCC_REJ_IND" },
	{ MNCC_BRIDGE, "MNCC_BRIDGE" },
	{ MNCC_FRAME_RECV, "MNCC_FRAME_RECV" },
	{ MNCC_FRAME_DROP, "MNCC_FRAME_DROP" },
	{ MNCC_LCHAN_MODIFY, "MNCC_LCHAN_MODIFY" },
	{ MNCC_RTP_CREATE, "MNCC_RTP_CREATE" },
	{ MNCC_RTP_CONNECT, "MNCC_RTP_CONNECT" },
	{ MNCC_RTP_FREE, "MNCC_RTP_FREE" },
	{ GSM_TCHF_FRAME, "GSM_TCHF_FRAME" },
	{ GSM_TCHF_FRAME_EFR, "GSM_TCHF_FRAME_EFR" },
	{ GSM_TCHH_FRAME, "GSM_TCHH_FRAME" },
	{ GSM_TCH_FRAME_AMR, "GSM_TCH_FRAME_AMR" },
	{ GSM_BAD_FRAME, "GSM_BAD_FRAME" },
	{ MNCC_SOCKET_HELLO, "MNCC_SOCKET_HELLO" },
	{ 0, NULL },
};

static void mncc_dump_rtp(struct msgb *str, const uint8_t *msg, unsigned int len)
{
	const struct gsm_mncc_rtp *rtp = (const struct gsm_mncc_rtp *) msg;
	struct in_addr ia;
	if (len < sizeof(*rtp)) {
		msgb_printf(str, "short MNCC RTP message (%u bytes)", len);
		return;
	}

	ia.s_addr = rtp->ip;
	msgb_printf(str, "%s(ref=0x%08x, ip=%s, port=%u, pt=%u, pt_mt=%u)",
			osmo_mncc_name(rtp->msg_type), rtp->callref, inet_ntoa(ia),
			ntohs(rtp->port), rtp->payload_type, rtp->payload_msg_type);
}

static void mncc_dump_data(struct msgb *str, const uint8_t *msg, unsigned int len)
{
	const struct gsm_data_frame *data = (const struct gsm_data_frame *) msg;
	if (len < sizeof(*data)) {
		msgb_printf(str, "short MNCC DATA message (%u bytes)", len);
		return;
	}

	msgb_printf(str, "%s(ref=0x%08x, data=%s)", osmo_mncc_name(data->msg_type), data->callref,
			osmo_hexdump_nospc(data->data, len - sizeof(*data)));
}

static void mncc_dump_hello(struct msgb *str, const uint8_t *msg, unsigned int len)
{
	const struct gsm_mncc_hello *hello = (const struct gsm_mncc_hello *) msg;
	if (len < sizeof(*hello)) {
		msgb_printf(str, "short MNCC HELLO message (%u bytes)", len);
		return;
	}

	msgb_printf(str, "%s(ver=%u, mncc_sz=%u, data_size=%u called_off=%u, signal_off=%u, "
		    "emerg_off=%u, lchan_t_off=%u)\n", osmo_mncc_name(hello->msg_type),
		    hello->version, hello->mncc_size, hello->data_frame_size, hello->called_offset,
		    hello->signal_offset, hello->emergency_offset, hello->lchan_type_offset);
}

static void msg_dump_number(struct msgb *str, const char *pfx, const struct gsm_mncc_number *num)
{
	msgb_printf(str, "%s(%d,%d,%d,%d,%s)", pfx, num->type, num->plan, num->present, num->screen,
			num->number);
}

static void mncc_dump_bridge(struct msgb *str, const uint8_t *msg, unsigned int len)
{
	const struct gsm_mncc_bridge *bridge = (const struct gsm_mncc_bridge *)msg;
	if (len < sizeof(*bridge)) {
		msgb_printf(str, "short MNCC BRIDGE message (%u bytes)", len);
		return;
	}

	msgb_printf(str, "%s(call_a=0x%08x, call_b=0x%08x)", osmo_mncc_name(bridge->msg_type),
			bridge->callref[0], bridge->callref[1]);
}

static void mncc_dump_sign(struct msgb *str, const uint8_t *msg, unsigned int len)
{
	const struct gsm_mncc *sign = (const struct gsm_mncc *) msg;
	if (len < sizeof(*sign)) {
		msgb_printf(str, "short MNCC SIGN message (%u bytes)", len);
		return;
	}

	msgb_printf(str, "%s(ref=0x%08x, imsi=%s", osmo_mncc_name(sign->msg_type), sign->callref,
		    sign->imsi);
	//if (sign->fields & MNCC_F_BEARER_CAP)
	//	msgb_printf(str, ", bcap=%s", osmo_hexdump_nospc());
	if (sign->fields & MNCC_F_CALLED)
		msg_dump_number(str, ", called=", &sign->called);
	if (sign->fields & MNCC_F_CALLING)
		msg_dump_number(str, ", calling=", &sign->calling);
	if (sign->fields & MNCC_F_REDIRECTING)
		msg_dump_number(str, ", redirecting=", &sign->redirecting);
	if (sign->fields & MNCC_F_CONNECTED)
		msg_dump_number(str, ", connected=", &sign->connected);
	if (sign->fields & MNCC_F_CAUSE) {
		msgb_printf(str, ", cause=(%d,%d,%d,%d,%d,'%s')", sign->cause.location,
			    sign->cause.coding, sign->cause.rec, sign->cause.rec_val,
			    sign->cause.value, sign->cause.diag_len ? sign->cause.diag : "");
	}
	if (sign->fields & MNCC_F_USERUSER) {
		msgb_printf(str, ", useruser=(%u, '%s')", sign->useruser.proto,
			    sign->useruser.info);
	}
	if (sign->fields & MNCC_F_PROGRESS) {
		msgb_printf(str, ", progress=(%d, %d, %d)", sign->progress.coding,
			    sign->progress.location, sign->progress.descr);
	}
	if (sign->fields & MNCC_F_EMERGENCY)
		msgb_printf(str, ", emergency=%d", sign->emergency);
	if (sign->fields & MNCC_F_FACILITY)
		msgb_printf(str, ", facility='%s'", sign->facility.info);
	if (sign->fields & MNCC_F_SSVERSION)
		msgb_printf(str, ", ssversion='%s'", sign->ssversion.info);
	if (sign->fields & MNCC_F_CCCAP)
		msgb_printf(str, ", cccap=(%d, %d)", sign->cccap.dtmf, sign->cccap.pcp);
	if (sign->fields & MNCC_F_KEYPAD)
		msgb_printf(str, ", keypad=%d", sign->keypad);
	if (sign->fields & MNCC_F_SIGNAL)
		msgb_printf(str, ", signal=%d", sign->signal);

	msgb_printf(str, ", clir.sup=%d, clir.inv=%d, more=%d, notify=%d)", sign->clir.sup,
		    sign->clir.inv, sign->more, sign->notify);
	/* lchan_type/lchan_mode? */
}


struct msgb *osmo_mncc_stringify(const uint8_t *msg, unsigned int len)
{
	uint32_t msg_type;
	struct msgb *str = msgb_alloc(2048, __func__);

	OSMO_ASSERT(str);

	if (len <= sizeof(msg_type)) {
		msgb_printf(str, "short MNCC message (%d bytes)", len);
		return NULL;
	}

	msg_type = *(const uint32_t *)msg;
	switch (msg_type) {
	case MNCC_RTP_CREATE:
	case MNCC_RTP_CONNECT:
	case MNCC_RTP_FREE:
		mncc_dump_rtp(str, msg, len);
		break;
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
	case GSM_TCHH_FRAME:
	case GSM_TCH_FRAME_AMR:
	case GSM_BAD_FRAME:
		mncc_dump_data(str, msg, len);
		break;
	case MNCC_SOCKET_HELLO:
		mncc_dump_hello(str, msg, len);
		break;
	case MNCC_BRIDGE:
		mncc_dump_bridge(str, msg, len);
		break;
	default:
		mncc_dump_sign(str, msg, len);
		break;
	}
	return str;
}

void _osmo_mncc_log(int ss, int level, const char *file, int line, const char *prefix,
		    const uint8_t *msg, unsigned int len)
{
	struct msgb *str;
	if (!log_check_level(ss, level))
		return;

	str = osmo_mncc_stringify(msg, len);
	if (!str)
		return;

	logp2(ss, level, file, line, 0, "%s%s\n", prefix, str->data);
	msgb_free(str);
}

#endif /* HAVE_SYS_SOCKET_H */
