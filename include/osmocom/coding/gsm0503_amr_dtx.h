/*! \file gsm0503_amr_dtx.h
 *  GSM TS 05.03 coding
 */

#pragma once

#include <stdint.h>

#include <osmocom/core/defs.h>
#include <osmocom/core/bits.h>

/*! \addtogroup coding
 *  @{
 * \file gsm0503_amr_dtx.h */

enum gsm0503_amr_dtx_frames {
	AMR_OTHER,
	AFS_SID_FIRST,
	AFS_SID_UPDATE,
	AFS_SID_UPDATE_CN,
	AFS_ONSET,
	AHS_SID_UPDATE,
	AHS_SID_UPDATE_CN,
	AHS_SID_FIRST_P1,
	AHS_SID_FIRST_P2,
	AHS_ONSET,
	AHS_SID_FIRST_INH,
	AHS_SID_UPDATE_INH,
};

extern const struct value_string gsm0503_amr_dtx_frame_names[];
static inline const char *gsm0503_amr_dtx_frame_name(enum gsm0503_amr_dtx_frames frame)
{
	return get_value_string(gsm0503_amr_dtx_frame_names, frame);
}

enum gsm0503_amr_dtx_frames gsm0503_detect_afs_dtx_frame(int *n_errors, int *n_bits_total, const ubit_t *ubits)
	OSMO_DEPRECATED("Use gsm0503_detect_afs_dtx_frame2() instead");
enum gsm0503_amr_dtx_frames gsm0503_detect_ahs_dtx_frame(int *n_errors, int *n_bits_total, const ubit_t *ubits)
	OSMO_DEPRECATED("Use gsm0503_detect_ahs_dtx_frame2() instead");

enum gsm0503_amr_dtx_frames gsm0503_detect_afs_dtx_frame2(int *n_errors, int *n_bits_total,
							  int *mode_id, const sbit_t *sbits);
enum gsm0503_amr_dtx_frames gsm0503_detect_ahs_dtx_frame2(int *n_errors, int *n_bits_total,
							  int *mode_id, const sbit_t *sbits);

/*! @} */
