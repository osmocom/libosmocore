/*! \file gsm0503_parity.h
 *  GSM TS 05.03 parity.
 */

#pragma once

#include <osmocom/core/crcgen.h>

/*! \addtogroup parity
 *  @{
 * \file gsm0503_parity.h */

extern const struct osmo_crc64gen_code gsm0503_fire_crc40;
extern const struct osmo_crc16gen_code gsm0503_cs234_crc16;
extern const struct osmo_crc8gen_code gsm0503_mcs_crc8_hdr;
extern const struct osmo_crc16gen_code gsm0503_mcs_crc12;
extern const struct osmo_crc8gen_code gsm0503_rach_crc6;
extern const struct osmo_crc16gen_code gsm0503_sch_crc10;
extern const struct osmo_crc8gen_code gsm0503_tch_fr_crc3;
extern const struct osmo_crc8gen_code gsm0503_tch_efr_crc8;
extern const struct osmo_crc8gen_code gsm0503_amr_crc6;
extern const struct osmo_crc16gen_code gsm0503_amr_crc14;

/*! @} */
