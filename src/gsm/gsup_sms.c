/*
 * (C) 2018 by Vadim Yanitskiy <axilirator@gmail.com>
 *
 * All Rights Reserved
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

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/tlv.h>

/*! \addtogroup gsup
 *  @{
 *  \file gsup_sms.c
 *  SMS (Short Message Service) extensions for Osmocom GSUP.
 */

/*! Encode SM-RP-DA IE (see 7.6.8.1), Destination Address.
 * \param[out] msg      target message buffer (caller-allocated)
 * \param[in]  gsup_msg abstract GSUP message structure
 * \returns 0 in case of success, negative in case of error
 */
int osmo_gsup_sms_encode_sm_rp_da(struct msgb *msg,
	const struct osmo_gsup_message *gsup_msg)
{
	uint8_t *id_enc;

	switch (gsup_msg->sm_rp_da_type) {
	case OSMO_GSUP_SMS_SM_RP_ODA_IMSI:
	case OSMO_GSUP_SMS_SM_RP_ODA_MSISDN:
	case OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR:
		/* Prevent NULL-pointer (or empty) dereference */
		if (gsup_msg->sm_rp_da == NULL || gsup_msg->sm_rp_da_len == 0) {
			LOGP(DLGSUP, LOGL_ERROR, "Empty?!? SM-RP-DA ID "
				"(type=0x%02x)!\n", gsup_msg->sm_rp_da_type);
			return -EINVAL;
		}
		break;

	/* Special case for noSM-RP-DA */
	case OSMO_GSUP_SMS_SM_RP_ODA_NULL:
		break;

	case OSMO_GSUP_SMS_SM_RP_ODA_NONE:
	default:
		LOGP(DLGSUP, LOGL_ERROR, "Unexpected SM-RP-DA ID "
			"(type=0x%02x)!\n", gsup_msg->sm_rp_da_type);
		return -EINVAL;
	}

	/* SM-RP-DA tag | len | ... */
	msgb_tv_put(msg, OSMO_GSUP_SM_RP_DA_IE, gsup_msg->sm_rp_da_len + 1);
	msgb_v_put(msg, gsup_msg->sm_rp_da_type); /* ... | id_type */

	if (gsup_msg->sm_rp_da_type == OSMO_GSUP_SMS_SM_RP_ODA_NULL)
		return 0;

	/* ... | id_enc */
	id_enc = msgb_put(msg, gsup_msg->sm_rp_da_len);
	memcpy(id_enc, gsup_msg->sm_rp_da, gsup_msg->sm_rp_da_len);

	return 0;
}

/*! Decode SM-RP-DA IE (see 7.6.8.1), Destination Address.
 * \param[out] gsup_msg abstract GSUP message structure
 * \param[in]  data     pointer to the raw IE payload
 * \param[in]  data_len length of IE pointed by \ref data
 * \returns 0 in case of success, negative in case of error
 */
int osmo_gsup_sms_decode_sm_rp_da(struct osmo_gsup_message *gsup_msg,
	uint8_t *data, size_t data_len)
{
	uint8_t *ptr = data;
	uint8_t id_type;

	/* There should be at least id_type */
	if (data_len < 1) {
		LOGP(DLGSUP, LOGL_ERROR, "Corrupted SM-RP-DA IE "
			"(missing identity type)\n");
		return -EINVAL;
	}

	/* ... | id_type | id_enc (optional) */
	id_type = *ptr++;
	data_len--;

	/* Parse ID type */
	switch (id_type) {
	case OSMO_GSUP_SMS_SM_RP_ODA_IMSI:
	case OSMO_GSUP_SMS_SM_RP_ODA_MSISDN:
	case OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR:
		if (!data_len) {
			/* ID shall not be empty (if its type != NULL) */
			LOGP(DLGSUP, LOGL_ERROR, "Corrupted SM-RP-DA IE "
				"(missing encoded identity)\n");
			return -EINVAL;
		}

		gsup_msg->sm_rp_da_type = id_type;
		gsup_msg->sm_rp_da_len = data_len;
		gsup_msg->sm_rp_da = ptr;
		break;

	/* Special case for noSM-RP-DA */
	case OSMO_GSUP_SMS_SM_RP_ODA_NULL:
		if (data_len != 0) {
			LOGP(DLGSUP, LOGL_ERROR, "Unexpected SM-RP-DA ID, "
				"(id_len != 0) for noSM-RP-DA!\n");
			return -EINVAL;
		}

		gsup_msg->sm_rp_da_type = id_type;
		gsup_msg->sm_rp_da_len = 0;
		gsup_msg->sm_rp_da = NULL;
		break;

	case OSMO_GSUP_SMS_SM_RP_ODA_NONE:
	default:
		LOGP(DLGSUP, LOGL_ERROR, "Unexpected SM-RP-DA ID "
			"(type=0x%02x)!\n", id_type);
		return -EINVAL;
	}

	return 0;
}

/*! Encode SM-RP-OA IE (see 7.6.8.2), Originating Address.
 * \param[out] msg      target message buffer (caller-allocated)
 * \param[in]  gsup_msg abstract GSUP message structure
 * \returns 0 in case of success, negative in case of error
 */
int osmo_gsup_sms_encode_sm_rp_oa(struct msgb *msg,
	const struct osmo_gsup_message *gsup_msg)
{
	uint8_t *id_enc;

	switch (gsup_msg->sm_rp_oa_type) {
	case OSMO_GSUP_SMS_SM_RP_ODA_MSISDN:
	case OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR:
		/* Prevent NULL-pointer (or empty) dereference */
		if (gsup_msg->sm_rp_oa == NULL || gsup_msg->sm_rp_oa_len == 0) {
			LOGP(DLGSUP, LOGL_ERROR, "Empty?!? SM-RP-OA ID "
				"(type=0x%02x)!\n", gsup_msg->sm_rp_oa_type);
			return -EINVAL;
		}
		break;

	/* Special case for noSM-RP-OA */
	case OSMO_GSUP_SMS_SM_RP_ODA_NULL:
		break;

	case OSMO_GSUP_SMS_SM_RP_ODA_NONE:
	default:
		LOGP(DLGSUP, LOGL_ERROR, "Unexpected SM-RP-OA ID "
			"(type=0x%02x)!\n", gsup_msg->sm_rp_oa_type);
		return -EINVAL;
	}

	/* SM-RP-OA tag | len | ... */
	msgb_tv_put(msg, OSMO_GSUP_SM_RP_OA_IE, gsup_msg->sm_rp_oa_len + 1);
	msgb_v_put(msg, gsup_msg->sm_rp_oa_type); /* ... | id_type */

	if (gsup_msg->sm_rp_oa_type == OSMO_GSUP_SMS_SM_RP_ODA_NULL)
		return 0;

	/* ... | id_enc */
	id_enc = msgb_put(msg, gsup_msg->sm_rp_oa_len);
	memcpy(id_enc, gsup_msg->sm_rp_oa, gsup_msg->sm_rp_oa_len);

	return 0;
}

/*! Decode SM-RP-OA IE (see 7.6.8.2), Originating Address.
 * \param[out] gsup_msg abstract GSUP message structure
 * \param[in]  data     pointer to the raw IE payload
 * \param[in]  data_len length of IE pointed by \ref data
 * \returns 0 in case of success, negative in case of error
 */
int osmo_gsup_sms_decode_sm_rp_oa(struct osmo_gsup_message *gsup_msg,
	uint8_t *data, size_t data_len)
{
	uint8_t *ptr = data;
	uint8_t id_type;

	/* There should be at least id_type */
	if (data_len < 1) {
		LOGP(DLGSUP, LOGL_ERROR, "Corrupted SM-RP-OA IE "
			"(missing identity type)\n");
		return -EINVAL;
	}

	/* ... | id_type | id_enc (optional) */
	id_type = *ptr++;
	data_len--;

	/* Parse ID type */
	switch (id_type) {
	case OSMO_GSUP_SMS_SM_RP_ODA_IMSI:
	case OSMO_GSUP_SMS_SM_RP_ODA_MSISDN:
	case OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR:
		if (!data_len) {
			/* ID shall not be empty (if its type != NULL) */
			LOGP(DLGSUP, LOGL_ERROR, "Corrupted SM-RP-OA IE "
				"(missing encoded identity)\n");
			return -EINVAL;
		}

		gsup_msg->sm_rp_oa_type = id_type;
		gsup_msg->sm_rp_oa_len = data_len;
		gsup_msg->sm_rp_oa = ptr;
		break;

	/* Special case for noSM-RP-DA */
	case OSMO_GSUP_SMS_SM_RP_ODA_NULL:
		if (data_len != 0) {
			LOGP(DLGSUP, LOGL_ERROR, "Unexpected SM-RP-OA ID, "
				"(id_len != 0) for noSM-RP-DA!\n");
			return -EINVAL;
		}

		gsup_msg->sm_rp_oa_type = id_type;
		gsup_msg->sm_rp_oa_len = 0;
		gsup_msg->sm_rp_oa = NULL;
		break;

	case OSMO_GSUP_SMS_SM_RP_ODA_NONE:
	default:
		LOGP(DLGSUP, LOGL_ERROR, "Unexpected SM-RP-OA ID "
			"(type=0x%02x)!\n", id_type);
		return -EINVAL;
	}

	return 0;
}

/*! @} */
