#pragma once

/*! \defgroup kdf key derivation functions
 *  @{
 * \file kdf.h */

#include <stdint.h>

void osmo_kdf_kc128(const uint8_t* ck, const uint8_t* ik, uint8_t* kc128);

void osmo_kdf_kasme(const uint8_t *ck, const uint8_t *ik, const uint8_t* plmn_id,
                    const uint8_t *sqn,  const uint8_t *ak, uint8_t *kasme);

void osmo_kdf_enb(const uint8_t *kasme, uint32_t ul_count, uint8_t *kenb);

void osmo_kdf_nh(const uint8_t *kasme, const uint8_t *sync_input, uint8_t *nh);

void osmo_kdf_nas(uint8_t algo_type, uint8_t algo_id, const uint8_t *kasme, uint8_t *knas);


/* @} */
