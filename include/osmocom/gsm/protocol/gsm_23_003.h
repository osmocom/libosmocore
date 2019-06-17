/*! \file gsm_23_003.h */

#pragma once

/* Chapter 2.2 */
#define GSM23003_IMSI_MAX_DIGITS	15
#define GSM23003_IMSI_MIN_DIGITS	6
/*! The char[] buffer size to completely contain an IMSI including the optional checksum digit as well as the
 * terminating nul character. */
#define OSMO_IMSI_BUF_SIZE (GSM23003_IMSI_MAX_DIGITS+2)
/* Chapter 2.4 */
#define GSM23003_TMSI_NUM_BYTES		4
#define GSM23003_TMSI_SGSN_MASK		0xC0000000UL
/* Chapter 2.5 */
#define GSM23003_LMSI_NUM_BYTES		4
/* Chapter 2.6 */
#define GSM23003_TLLI_NUM_BYTES		4
/* Chapter 2.7 */
#define GSM23003_PTMSI_SIG_NUM_BYTES	3
/* Chapter 2.8 */
#define GSM23003_MME_CODE_NUM_BYTES	1
#define GSM23003_MME_GROUP_NUM_BYTES	2
#define GSM23003_MTMSI_NUM_BYTES	4
/* Chapter 3.2 */
#define GSM23003_MSISDN_MAX_DIGITS	15 /* ITU-T Rec. E.164 6.1 */
#define GSM23003_MSISDN_MIN_DIGITS	1
/* Chapter 6.2.1 */
#define GSM23003_IMEI_TAC_NUM_DIGITS	8
#define GSM23003_IMEI_SNR_NUM_DIGITS	6
#define GSM23003_IMEI_NUM_DIGITS	(GSM23003_IMEI_TAC_NUM_DIGITS + \
					 GSM23003_IMEI_SNR_NUM_DIGITS + 1)
#define GSM23003_IMEISV_NUM_DIGITS	(GSM23003_IMEI_TAC_NUM_DIGITS + \
					 GSM23003_IMEI_SNR_NUM_DIGITS + 2)
/* IMEI without Luhn checksum */
#define GSM23003_IMEI_NUM_DIGITS_NO_CHK	(GSM23003_IMEI_TAC_NUM_DIGITS + \
					 GSM23003_IMEI_SNR_NUM_DIGITS)

/* Chapter 19.2 "epc.mnc000.mcc000.3gppnetwork.org" */
#define GSM23003_HOME_NETWORK_DOMAIN_LEN	33

/* Chapter 19.4.2.4: "mmec00.mmegi0000.mme.epc.mnc000.mcc000.3gppnetwork.org" */
#define GSM23003_MME_DOMAIN_LEN			55
