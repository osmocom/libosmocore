#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/bitvec.h>

#define INTRO(p) printf("=== start %s(%u) ===\n", __func__, p)
#define OUTRO(p) printf("=== end %s(%u) ===\n\n", __func__, p)

static void test_bitvec_ia_octet_encode_pkt_dl_ass(struct bitvec *dest, uint32_t ttli,
						   uint8_t tfi, uint8_t gamma, uint8_t ta_valid, uint8_t ws_enc,
						   bool use_lh)
{
	unsigned wp = 0;

	INTRO(use_lh);

	/* 3GPP TS 44.018 §10.5.2.16 IA Rest Octets */
	if (use_lh) /* FIXME: add function to encode LH properly */
		bitvec_write_field(dest, &wp, 3, 2);		/* "HH" */
	else
		bitvec_write_field(dest, &wp, 3, 2);		/* "HH" */
	bitvec_write_field(dest, &wp, 1, 2);			/* "01" Packet Downlink Assignment */
	bitvec_write_field(dest, &wp, ttli, 32);		/* TLLI */
	bitvec_write_field(dest, &wp, 1, 1);			/* switch TFI: on */
	bitvec_write_field(dest, &wp, tfi, 5);			/* TFI */
	bitvec_write_field(dest, &wp, 0x0, 1);			/* RLC acknowledged mode */
	bitvec_write_field(dest, &wp, 0x0, 1);			/* ALPHA = not present */
	bitvec_write_field(dest, &wp, gamma, 5);		/* GAMMA power control parameter */
	bitvec_write_field(dest, &wp, 0,1);			/* Polling Bit: off */
	bitvec_write_field(dest, &wp, ta_valid, 1);		/* N. B: NOT related to TAI! */
	bitvec_write_field(dest, &wp, 0, 1);			/* No TIMING_ADVANCE_INDEX: */
	bitvec_write_field(dest, &wp, 0, 1);			/* TBF Starting TIME present */
	bitvec_write_field(dest, &wp, 0, 1);			/* P0 not present */
	if (use_lh) { /* FIXME: add function to encode LH properly */
		bitvec_write_field(dest, &wp, 1, 1);		/* "H" - additional for R99 */
	} else
		bitvec_write_field(dest, &wp, 1, 1);		/* "H" - additional for R99 */
	bitvec_write_field(dest, &wp, ws_enc, 5);		/* EGPRS Window Size */
	bitvec_write_field(dest, &wp, 0, 2);			/* LINK_QUALITY_MEASUREMENT_MODE */
	bitvec_write_field(dest, &wp, 0, 1);			/* BEP_PERIOD2 not present */

	printf("Encoded PKT DL ASS IA Rest Octets: %s\n", osmo_hexdump(dest->data, dest->data_len));

	OUTRO(use_lh);
}

static void test_bitvec_ia_octet_encode_pkt_ul_ass(struct bitvec *dest, uint32_t fn,
						   uint8_t tfi, uint8_t gamma, uint8_t usf, bool tbf, bool use_lh)
{
	unsigned wp = 0;

	INTRO(use_lh);

	/* 3GPP TS 44.018 §10.5.2.37b 10.5.2.16 */
	if (use_lh) /* FIXME: add function to encode LH properly */
		bitvec_write_field(dest, &wp, 3, 2);				/* "HH" */
	else
		bitvec_write_field(dest, &wp, 3, 2);				/* "HH" */
	bitvec_write_field(dest, &wp, 0, 2);					/* "0" Packet Uplink Assignment */
	if (!tbf) {
		bitvec_write_field(dest, &wp, 0, 1);				/* Block Allocation: SBA */
		bitvec_write_field(dest, &wp, 0, 1);				/* ALPHA = not present */
		bitvec_write_field(dest, &wp, gamma, 5);			/* GAMMA power control parameter */
		bitvec_write_field(dest, &wp, 0, 1);				/* No TIMING_ADVANCE_INDEX: */
		bitvec_write_field(dest, &wp, 1, 1); 				/* TBF_STARTING_TIME_FLAG */
		bitvec_write_field(dest, &wp, (fn / (26 * 51)) % 32, 5);	/* T1' */
		bitvec_write_field(dest, &wp, fn % 51, 6);			/* T3 */
		bitvec_write_field(dest, &wp, fn % 26, 5);			/* T2 */
	} else {
		bitvec_write_field(dest, &wp, 1, 1);				/* Block Allocation: Not SBA */
		bitvec_write_field(dest, &wp, tfi, 5);				/* TFI_ASSIGNMENT */
		bitvec_write_field(dest, &wp, 0, 1);				/* POLLING = none */
		bitvec_write_field(dest, &wp, 0, 1);				/* ALLOCATION_TYPE: dynamic */
		bitvec_write_field(dest, &wp, usf, 3);				/* USF */
		bitvec_write_field(dest, &wp, 0, 1);				/* USF_GRANULARITY */
		bitvec_write_field(dest, &wp, 0, 1);				/* "0" power control: Not Present */
		bitvec_write_field(dest, &wp, 0, 2);				/* CHANNEL_CODING_COMMAND */
		bitvec_write_field(dest, &wp, 1, 1);				/* TLLI_BLOCK_CHANNEL_CODING */
		bitvec_write_field(dest, &wp, 0, 1);				/* ALPHA = not present */
		bitvec_write_field(dest, &wp, gamma, 5);			/* GAMMA power control parameter */
		/* note: there is no choise for TAI and no starting time */
		bitvec_write_field(dest, &wp, 0, 1);				/* switch TIMING_ADVANCE_INDEX = off */
		bitvec_write_field(dest, &wp, 0, 1);				/* TBF_STARTING_TIME_FLAG */
	}

	printf("Encoded PKT UL ASS IA Rest Octets: %s\n", osmo_hexdump(dest->data, dest->data_len));

	OUTRO(use_lh);
}

static void test_bitdiff(const struct bitvec *src1, const struct bitvec *src2, unsigned len)
{
	unsigned int bit_err = 0, i, j;
	uint8_t byte_err = 0;

	INTRO(len);

	for (i = 0; i < len; i++) {
		/* byte compare */
		byte_err = src1->data[i] ^ src2->data[i];
		if (byte_err)
			for (j = 0; j < 8; j++)
				bit_err += (byte_err >> j) & 0x01; /* count bits which differ */
	}


	printf("=== total %u bits differ ===\n", bit_err);

	OUTRO(len);
}

static inline void buf_init(struct bitvec *dest, struct bitvec *dest_lh)
{
	/* initialize buffer */
	bitvec_unhex(dest, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	bitvec_unhex(dest_lh, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
}

static inline void test_enc_ul_ass(struct bitvec *dest, struct bitvec *dest_lh, uint32_t fn,
				   uint8_t tfi, uint8_t gamma, uint8_t usf, bool tbf)
{
	buf_init(dest, dest_lh);

	test_bitvec_ia_octet_encode_pkt_ul_ass(dest, fn, tfi, gamma, usf, tbf, false);
	test_bitvec_ia_octet_encode_pkt_ul_ass(dest_lh, fn, tfi, gamma, usf, tbf, true);

	test_bitdiff(dest, dest_lh, 22);
}

int main(int argc, char **argv)
{
	void *tall_pcu_ctx;
	struct bitvec *dest, *dest_lh;
	uint8_t gamma = 0, ta_valid = 1, ws_enc = 3, usf = 1, tfi = 0; /* Temporary Flow Identity */
	uint32_t ttli = 0xdeadbeef, fn = 1234;

	tall_pcu_ctx = talloc_named_const(NULL, 1, "bitvecTest context");
	if (!tall_pcu_ctx)
		return EXIT_FAILURE;

	dest = bitvec_alloc(22, tall_pcu_ctx);
	dest_lh = bitvec_alloc(22, tall_pcu_ctx);

	buf_init(dest, dest_lh);

	test_bitvec_ia_octet_encode_pkt_dl_ass(dest, ttli, tfi, gamma, ta_valid, ws_enc, false);
	test_bitvec_ia_octet_encode_pkt_dl_ass(dest_lh, ttli, tfi, gamma, ta_valid, ws_enc, true);

	test_bitdiff(dest, dest_lh, 22);

	test_enc_ul_ass(dest, dest_lh, fn, tfi, gamma, usf, false);
	test_enc_ul_ass(dest, dest_lh, fn, tfi, gamma, usf, true);

	bitvec_free(dest);
	bitvec_free(dest_lh);

	talloc_free(tall_pcu_ctx);

	return EXIT_SUCCESS;
}
