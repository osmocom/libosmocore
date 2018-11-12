#pragma once

/*! \addtogroup gsup
 *  @{
 *
 *  This header defines SMS (Short Message Service) extensions for
 *  Osmocom GSUP (Generic Subscriber Update Protocol). The scope of
 *  this module is defined by 3GPP TS 29.002, section 12.
 *
 *  \file gsup_sms.h
 *  SMS (Short Message Service) extensions for Osmocom GSUP. */

#include <stdint.h>

/*! Possible identity types for SM-RP-{OA|DA} */
enum osmo_gsup_sms_sm_rp_oda_t {
	OSMO_GSUP_SMS_SM_RP_ODA_NONE		= 0x00,
	OSMO_GSUP_SMS_SM_RP_ODA_IMSI		= 0x01,
	OSMO_GSUP_SMS_SM_RP_ODA_MSISDN		= 0x02,
	OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR	= 0x03,
	/*! Special value for noSM-RP-DA and noSM-RP-OA */
	OSMO_GSUP_SMS_SM_RP_ODA_NULL		= 0xff,
};

/*! Alert reason values, see 7.6.8.8 */
enum osmo_gsup_sms_sm_alert_rsn_t {
	OSMO_GSUP_SMS_SM_ALERT_RSN_NONE		= 0x00,
	OSMO_GSUP_SMS_SM_ALERT_RSN_MS_PRESENT	= 0x01,
	OSMO_GSUP_SMS_SM_ALERT_RSN_MEM_AVAIL	= 0x02,
};

struct osmo_gsup_message;
struct msgb;

int osmo_gsup_sms_encode_sm_rp_da(struct msgb *msg,
	const struct osmo_gsup_message *gsup_msg);
int osmo_gsup_sms_decode_sm_rp_da(struct osmo_gsup_message *gsup_msg,
	uint8_t *data, size_t data_len);

int osmo_gsup_sms_encode_sm_rp_oa(struct msgb *msg,
	const struct osmo_gsup_message *gsup_msg);
int osmo_gsup_sms_decode_sm_rp_oa(struct osmo_gsup_message *gsup_msg,
	uint8_t *data, size_t data_len);

/*! @} */
