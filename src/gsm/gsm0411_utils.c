/* Point-to-Point (PP) Short Message Service (SMS)
 * Support on Mobile Radio Interface
 * 3GPP TS 04.11 version 7.1.0 Release 1998 / ETSI TS 100 942 V7.1.0 */

/* (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * (C) 2011 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2014 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
 *
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

#include "../../config.h"

#include <time.h>
#include <string.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0411_utils.h>
#include <osmocom/gsm/protocol/gsm_03_40.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#define GSM411_ALLOC_SIZE	1024
#define GSM411_ALLOC_HEADROOM	128

struct msgb *gsm411_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM411_ALLOC_SIZE, GSM411_ALLOC_HEADROOM,
				   "GSM 04.11");
}

/* Turn int into semi-octet representation: 98 => 0x89 */
uint8_t gsm411_bcdify(uint8_t value)
{
	uint8_t ret;

	ret = value / 10;
	ret |= (value % 10) << 4;

	return ret;
}

/* Turn semi-octet representation into int: 0x89 => 98 */
uint8_t gsm411_unbcdify(uint8_t value)
{
	uint8_t ret;

	if ((value & 0x0F) > 9 || (value >> 4) > 9)
		LOGP(DLSMS, LOGL_ERROR,
		     "gsm411_unbcdify got too big nibble: 0x%02X\n", value);

	ret = (value&0x0F)*10;
	ret += value>>4;

	return ret;
}

/* Generate 03.40 TP-SCTS */
void gsm340_gen_scts(uint8_t *scts, time_t time)
{
	struct tm *tm = gmtime(&time);

	*scts++ = gsm411_bcdify(tm->tm_year % 100);
	*scts++ = gsm411_bcdify(tm->tm_mon + 1);
	*scts++ = gsm411_bcdify(tm->tm_mday);
	*scts++ = gsm411_bcdify(tm->tm_hour);
	*scts++ = gsm411_bcdify(tm->tm_min);
	*scts++ = gsm411_bcdify(tm->tm_sec);
#ifdef HAVE_TM_GMTOFF_IN_TM
	if (tm->tm_gmtoff >= 0)
		*scts++ = gsm411_bcdify(tm->tm_gmtoff/(60*15));
	else
		*scts++ = gsm411_bcdify(-tm->tm_gmtoff/(60*15)) | 0x80;
#else
#warning find a portable way to obtain timezone offset
	*scts++ = 0;
#endif
}

/* Decode 03.40 TP-SCTS (into utc/gmt timestamp) */
time_t gsm340_scts(uint8_t *scts)
{
	struct tm tm;
	uint8_t yr, tz;
	int ofs;
	time_t timestamp;

	memset(&tm, 0x00, sizeof(struct tm));

	yr = gsm411_unbcdify(*scts++);
	if (yr <= 80)
		tm.tm_year = 100 + yr;
	else
		tm.tm_year = yr;
	tm.tm_mon  = gsm411_unbcdify(*scts++) - 1;
	tm.tm_mday = gsm411_unbcdify(*scts++);
	tm.tm_hour = gsm411_unbcdify(*scts++);
	tm.tm_min  = gsm411_unbcdify(*scts++);
	tm.tm_sec  = gsm411_unbcdify(*scts++);

	/* according to gsm 03.40 time zone is
	   "expressed in quarters of an hour" */
	tz = *scts++;
	ofs = gsm411_unbcdify(tz&0x7f) * 15*60;
	if (tz&0x80)
		ofs = -ofs;
	/* mktime() doesn't take tm.tm_gmtoff into account. Instead, it fills this
	 * field with the current timezone. Which means that the resulting time is
	 * off by several hours after that. So here we're setting tm.tm_isdt to -1
	 * to indicate that the tm time is local, but later we subtract the
	 * offset introduced by mktime. */
	tm.tm_isdst = -1;

	timestamp = mktime(&tm);
	if (timestamp < 0)
		return -1;

	/* Take into account timezone offset */
	timestamp -= ofs;
#ifdef HAVE_TM_GMTOFF_IN_TM
	/* Remove an artificial timezone offset, introduced by mktime() */
	timestamp += tm.tm_gmtoff;
#endif

	return timestamp;
}

/* Decode validity period format 'relative'.
 * Returns number of seconds relative to a current time. */
static time_t gsm340_vp_relative(uint8_t *sms_vp)
{
	/* Chapter 9.2.3.12.1 */
	uint8_t vp;
	time_t minutes;

	vp = *(sms_vp);
	if (vp <= 143)
		minutes = (vp + 1) * 5;
	else if (vp <= 167)
		minutes = 12*60 + (vp-143) * 30;
	else if (vp <= 196)
		minutes = (vp-166) * 60 * 24;
	else
		minutes = (vp-192) * 60 * 24 * 7;

	/* Convert to seconds */
	return minutes * 60;
}

/* Decode validity period format 'absolute'.
 * Returns UNIX time. */
static time_t gsm340_vp_absolute(uint8_t *sms_vp)
{
	/* Chapter 9.2.3.12.2 */
	return gsm340_scts(sms_vp);
}

/* Decode validity period format 'relative in integer representation'.
 * Returns number of seconds relative to a current time. */
static time_t gsm340_vp_relative_integer(uint8_t *sms_vp)
{
	uint8_t vp;
	vp = *(sms_vp);
	if (vp == 0) {
		LOGP(DLSMS, LOGL_ERROR,
		     "reserved relative_integer validity period\n");
#warning We should return an RP-Error here.
		return SMS_DEFAULT_VALIDITY_PERIOD;
	}
	return vp;
}

/* Decode validity period format 'relative in semi-octet representation'.
 * Returns number of seconds relative to a current time. */
static time_t gsm340_vp_relative_semioctet(uint8_t *sms_vp)
{
	time_t hours, minutes, seconds;
	hours   = gsm411_unbcdify(*sms_vp++); /* hours */
	minutes = gsm411_unbcdify(*sms_vp++); /* minutes */
	seconds = gsm411_unbcdify(*sms_vp++); /* seconds */
	return hours*60*60 + minutes*60 + seconds;
}

/* Decode validity period. Returns absolute UNIX time. */
time_t gsm340_validity_time(time_t now, uint8_t sms_vpf, uint8_t *sms_vp)
{
	uint8_t fi; /* functionality indicator */

	switch (sms_vpf) {
	case GSM340_TP_VPF_RELATIVE:
		return now + gsm340_vp_relative(sms_vp);
	case GSM340_TP_VPF_ABSOLUTE:
		return gsm340_vp_absolute(sms_vp);
	case GSM340_TP_VPF_ENHANCED:
		/* Chapter 9.2.3.12.3 */
		fi = *sms_vp++;
		/* ignore additional fi */
		if (fi & (1<<7)) sms_vp++;
		/* read validity period format */
		switch (fi & 0x7) {
		case 0x0:
			return now + SMS_DEFAULT_VALIDITY_PERIOD; /* no vpf specified */
		case 0x1:
			return now + gsm340_vp_relative(sms_vp);
		case 0x2:
			return now + gsm340_vp_relative_integer(sms_vp);
		case 0x3:
			return now + gsm340_vp_relative_semioctet(sms_vp);
		default:
			/* The GSM spec says that the SC should reject any
			   unsupported and/or undefined values. FIXME */
			LOGP(DLSMS, LOGL_ERROR,
			     "Reserved enhanced validity period format\n");
			return now + SMS_DEFAULT_VALIDITY_PERIOD;
		}
	case GSM340_TP_VPF_NONE:
	default:
		return now + SMS_DEFAULT_VALIDITY_PERIOD;
	}
}

/* Decode validity period. return relative minutes.
 * This behaviour is broken, but we're mimicing to it for compatibility. */
unsigned long gsm340_validity_period(uint8_t sms_vpf, uint8_t *sms_vp)
{
	time_t now = time(NULL);
	return (gsm340_validity_time(now, sms_vpf, sms_vp) - now) / 60;
}

/* determine coding alphabet dependent on GSM 03.38 Section 4 DCS */
enum sms_alphabet gsm338_get_sms_alphabet(uint8_t dcs)
{
	uint8_t cgbits = dcs >> 4;
	enum sms_alphabet alpha = DCS_NONE;

	if ((cgbits & 0xc) == 0) {
		if (cgbits & 2) {
			LOGP(DLSMS, LOGL_NOTICE,
			     "Compressed SMS not supported yet\n");
			return 0xffffffff;
		}

		switch ((dcs >> 2)&0x03) {
		case 0:
			alpha = DCS_7BIT_DEFAULT;
			break;
		case 1:
			alpha = DCS_8BIT_DATA;
			break;
		case 2:
			alpha = DCS_UCS2;
			break;
		}
	} else if (cgbits == 0xc || cgbits == 0xd)
		alpha = DCS_7BIT_DEFAULT;
	else if (cgbits == 0xe)
		alpha = DCS_UCS2;
	else if (cgbits == 0xf) {
		if (dcs & 4)
			alpha = DCS_8BIT_DATA;
		else
			alpha = DCS_7BIT_DEFAULT;
	}

	return alpha;
}

/* generate a TPDU address field compliant with 03.40 sec. 9.1.2.5 */
int gsm340_gen_oa(uint8_t *oa, unsigned int oa_len, uint8_t type,
	uint8_t plan, const char *number)
{
	int len_in_bytes;

	oa[1] = 0x80 | (type << 4) | plan;

	if (type == GSM340_TYPE_ALPHA_NUMERIC) {
		/*
		 * TODO/FIXME: what is the 'useful semi-octets' excluding any
		 * semi octet containing only fill bits.
		 * The current code picks the number of bytes written by the
		 * 7bit encoding routines and multiplies it by two.
		 */
		gsm_7bit_encode_n(&oa[2], oa_len - 2, number, &len_in_bytes);
		oa[0] = len_in_bytes * 2;
		len_in_bytes += 2;
	} else {
		/* prevent buffer overflows */
		if (strlen(number) > 20)
			number = "";
		len_in_bytes = gsm48_encode_bcd_number(oa, oa_len, 1, number);
		/* GSM 03.40 tells us the length is in 'useful semi-octets' */
		oa[0] = strlen(number) & 0xff;
	}

	return len_in_bytes;
}

/* Prefix msg with a RP header */
int gsm411_push_rp_header(struct msgb *msg, uint8_t rp_msg_type,
	uint8_t rp_msg_ref)
{
	struct gsm411_rp_hdr *rp;
	uint8_t len = msg->len;

	/* GSM 04.11 RP-DATA header */
	rp = (struct gsm411_rp_hdr *)msgb_push(msg, sizeof(*rp));
	rp->len = len + 2;
	rp->msg_type = rp_msg_type;
	rp->msg_ref = rp_msg_ref; /* FIXME: Choose randomly */

	return 0;
}

/* Prefix msg with a 04.08/04.11 CP header */
int gsm411_push_cp_header(struct msgb *msg, uint8_t proto, uint8_t trans,
			     uint8_t msg_type)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	/* Outgoing needs the highest bit set */
	gh->proto_discr = proto | (trans << 4);
	gh->msg_type = msg_type;

	return 0;
}
