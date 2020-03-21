/*! \file sim_int.h */

#ifndef _SIM_INT_H

#include <osmocom/sim/sim.h>

struct osim_decoded_element *
element_alloc(struct osim_decoded_data *dd, const char *name,
	      enum osim_element_type type, enum osim_element_repr repr);

struct osim_decoded_element *
element_alloc_sub(struct osim_decoded_element *ee, const char *name,
	      enum osim_element_type type, enum osim_element_repr repr);

int default_decode(struct osim_decoded_data *dd,
		   const struct osim_file_desc *desc,
		   int len, uint8_t *data);

void add_filedesc(struct osim_file_desc *root, const struct osim_file_desc *in, int num);
struct osim_file_desc *alloc_df(void *ctx, uint16_t fid, const char *name);
struct osim_file_desc *
add_df_with_ef(struct osim_file_desc *parent,
		uint16_t fid, const char *name,
		const struct osim_file_desc *in, int num);

struct osim_file_desc *
alloc_adf_with_ef(void *ctx, const uint8_t *adf_name, uint8_t adf_name_len,
		  const char *name, const struct osim_file_desc *in, int num);

extern const struct osim_reader_ops pcsc_reader_ops;

void osim_app_profile_register(struct osim_card_app_profile *aprof);

struct osim_card_app_profile *osim_aprof_usim(void *ctx);
struct osim_card_app_profile *osim_aprof_isim(void *ctx);
struct osim_card_app_profile *osim_aprof_hpsim(void *ctx);

#endif
