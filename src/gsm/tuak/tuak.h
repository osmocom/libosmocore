#pragma once
#include <stdint.h>

/* low-level functions */

int tuak_f1(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes, const uint8_t *_rand,
	    const uint8_t *sqn, const uint8_t *amf, uint8_t *mac_a, uint8_t mac_a_len_bytes,
	    unsigned int keccac_iterations);

int tuak_f1star(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes, const uint8_t *_rand,
		const uint8_t *sqn, const uint8_t *amf, uint8_t *mac_s, uint8_t mac_s_len_bytes,
		unsigned int keccac_iterations);

int tuak_f2345(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes,
	       const uint8_t *_rand, uint8_t *res, uint8_t res_len_bytes,
	       uint8_t *ck, uint8_t ck_len_bytes,
	       uint8_t *ik, uint8_t ik_len_bytes, uint8_t *ak, unsigned int keccac_iterations);

int tuak_f5star(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes,
		const uint8_t *_rand, uint8_t *ak, unsigned int keccac_iterations);

/* high-level API */

void tuak_set_keccak_iterations(unsigned int i);

void tuak_generate(const uint8_t *opc, const uint8_t *amf, const uint8_t *k, uint8_t k_len_bytes,
		   const uint8_t *sqn, const uint8_t *_rand, uint8_t *autn, uint8_t *ik,
		   uint8_t *ck, uint8_t *res, size_t *res_len);

int tuak_auts(const uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes,
	      const uint8_t *_rand, const uint8_t *auts, uint8_t *sqn);

int tuak_opc_gen(uint8_t *opc, const uint8_t *k, uint8_t k_len_bytes, const uint8_t *op);
