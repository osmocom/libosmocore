/*! \file mncc.h */

#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>

#define GSM_MAX_FACILITY       128
#define GSM_MAX_SSVERSION      128
#define GSM_MAX_USERUSER       128

/* Expanded fields from GSM TS 04.08, Table 10.5.102 */
struct gsm_mncc_bearer_cap {
	int		transfer;	/* Information Transfer Capability, see enum gsm48_bcap_itcap. */
	int 		mode;		/* Transfer Mode, see enum gsm48_bcap_tmod. */
	int		coding;		/* Coding Standard, see enum gsm48_bcap_coding.*/
	int		radio;		/* Radio Channel Requirement, see enum gsm48_bcap_rrq. */
	int		speech_ctm;	/* CTM text telephony indication */
	int		speech_ver[8];	/* Speech version indication, see enum gsm48_bcap_speech_ver; -1 marks end */
	struct {
		enum gsm48_bcap_ra		rate_adaption;
		enum gsm48_bcap_sig_access	sig_access;
		int				async;
		int				nr_stop_bits;
		int				nr_data_bits;
		enum gsm48_bcap_user_rate	user_rate;
		enum gsm48_bcap_parity		parity;
		enum gsm48_bcap_interm_rate	interm_rate;
		enum gsm48_bcap_transp		transp;
		enum gsm48_bcap_modem_type	modem_type;
	} data;
};

struct gsm_mncc_number {
	int 		type;
	int 		plan;
	int		present;
	int		screen;
	char		number[33];
};

struct gsm_mncc_cause {
	int		location;
	int		coding;
	int		rec;
	int		rec_val;
	int		value;
	int		diag_len;
	char		diag[32];
};

struct gsm_mncc_useruser {
	int		proto;
	char		info[GSM_MAX_USERUSER + 1]; /* + termination char */
};

struct gsm_mncc_progress {
	int		coding;
	int		location;
	int 		descr;
};

struct gsm_mncc_facility {
	int		len;
	char		info[GSM_MAX_FACILITY];
};

struct gsm_mncc_ssversion {
	int		len;
	char		info[GSM_MAX_SSVERSION];
};

struct gsm_mncc_cccap {
	int		dtmf;
	int		pcp;
};

enum {
	GSM_MNCC_BCAP_SPEECH	= 0,
	GSM_MNCC_BCAP_UNR_DIG	= 1,
	GSM_MNCC_BCAP_AUDIO	= 2,
	GSM_MNCC_BCAP_FAX_G3	= 3,
	GSM_MNCC_BCAP_OTHER_ITC = 5,
	GSM_MNCC_BCAP_RESERVED	= 7,
};

struct msgb;
struct msgb *osmo_mncc_stringify(const uint8_t *msg, unsigned int len);

void _osmo_mncc_log(int subsys, int level, const char *file, int line, const char *prefix,
		    const uint8_t *msg, unsigned int len);

#define osmo_mncc_log(ss, level, prefix, msg, len)	\
	_osmo_mncc_log(ss, level, __FILE__, __LINE__, prefix, msg, len);

extern const struct value_string osmo_mncc_names[];
static inline const char *osmo_mncc_name(uint32_t msg_type) {
	return get_value_string(osmo_mncc_names, msg_type);
}
