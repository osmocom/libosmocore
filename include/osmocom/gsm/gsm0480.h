/*! \file gsm0480.h */

#pragma once

#include <osmocom/core/defs.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>

extern const struct value_string gsm0480_comp_type_names[];
static inline const char *gsm0480_comp_type_name(uint8_t comp_type) {
	return get_value_string(gsm0480_comp_type_names, comp_type);
}

extern const struct value_string gsm0480_op_code_names[];
static inline const char *gsm0480_op_code_name(uint8_t op_code) {
	return get_value_string(gsm0480_op_code_names, op_code);
}

/**
 * According to the GSM 04.80 (version 5.0.0) specification Annex A
 * "Expanded ASN.1 Module "SS-Protocol", the maximum size of a USSD
 * OCTET STRING field is 160 bytes.
 */
#define GSM0480_USSD_OCTET_STRING_LEN	160

/**
 * Thus according to ETSI TS 123 038 (version 10.0.0) specification
 * 6.1.2.3 "USSD packing of 7 bit characters", in 160 octets, it's
 * possible to pack (160 * 8) / 7 = 182.8, that is 182 characters.
 * The remaining 6 bits are set to zero.
 */
#define GSM0480_USSD_7BIT_STRING_LEN	182

/**
 * DEPRECATED: this definition doesn't follow any specification,
 * so we only keep it for compatibility reasons. It's strongly
 * recommended to use correct definitions above.
 */
#define MAX_LEN_USSD_STRING		31

/* deprecated */
struct ussd_request {
	char text[MAX_LEN_USSD_STRING + 1];
	uint8_t transaction_id;
	uint8_t invoke_id;
};

/* deprecated */
int gsm0480_decode_ussd_request(const struct gsm48_hdr *hdr, uint16_t len,
				struct ussd_request *request) OSMO_DEPRECATED("Use gsm0480_decode_ss_request() instead");

/**
 * This structure represents some meaningful parts of
 * a decoded and/or to be encoded GSM 04.80 message.
 */
struct ss_request {
	/**
	 * GSM TS 04.80, section 3.6.4 "Operation code"
	 * See GSM0480_OP_CODE_* for possible values.
	 */
	uint8_t opcode;
	/**
	 * GSM TS 04.80, section 4.4.3.9 "ss-Code"
	 * The ss-Code identifier refers to the code which identify
	 * a supplementary service or a group of supplementary services.
	 */
	uint8_t ss_code;

	/**
	 * A rudiment of deprecated 'ussd_request' structure.
	 * Represents the data of either an INVOKE, either
	 * a RETURN_RESULT component, encoded as ASCII in
	 * case if DCS is 0x0f (i.e. decoded by the code
	 * itself), otherwise raw bytes 'as is'.
	 */
	uint8_t ussd_text[GSM0480_USSD_OCTET_STRING_LEN];

	/**
	 * Represents the data of either an INVOKE, either
	 * a RETURN_RESULT component 'as is'. Useful when
	 * decoding is not supported or not desired.
	 *
	 * Shall be always followed by its length (in bytes)
	 * and DCS (Data Coding Scheme).
	 */
	uint8_t ussd_data[GSM0480_USSD_OCTET_STRING_LEN];
	uint8_t ussd_data_len; /* Length in bytes */
	uint8_t ussd_data_dcs; /* Data Coding Scheme */

	/**
	 * GSM TS 04.80, section 3.3 "Transaction identifier"
	 * See GSM TS 04.07, section 11.2.3 for details.
	 */
	uint8_t transaction_id;
	/**
	 * GSM TS 04.80, section 3.6.3 "Component ID tag"
	 * The term Component ID refers to the Invoke ID or
	 * the Linked ID.
	 */
	uint8_t invoke_id;
};

int gsm0480_extract_ie_by_tag(const struct gsm48_hdr *hdr, uint16_t msg_len,
			      uint8_t **ie, uint16_t *ie_len, uint8_t ie_tag);
int gsm0480_parse_facility_ie(const uint8_t *facility_ie, uint16_t length,
			      struct ss_request *req);
int gsm0480_decode_ss_request(const struct gsm48_hdr *hdr, uint16_t len,
				struct ss_request *request);

struct msgb *gsm0480_msgb_alloc_name(const char *name);
struct msgb *gsm0480_gen_ussd_resp_7bit(uint8_t invoke_id, const char *text);
struct msgb *gsm0480_gen_return_error(uint8_t invoke_id, uint8_t error_code);
struct msgb *gsm0480_gen_reject(int invoke_id, uint8_t problem_tag, uint8_t problem_code);

struct msgb *gsm0480_create_ussd_resp(uint8_t invoke_id, uint8_t trans_id, const char *text);
struct msgb *gsm0480_create_unstructuredSS_Notify(int alertPattern, const char *text);
struct msgb *gsm0480_create_notifySS(const char *text);
struct msgb *gsm0480_create_ussd_notify(int level, const char *text);
struct msgb *gsm0480_create_ussd_release_complete(void);

int gsm0480_wrap_invoke(struct msgb *msg, int op, int link_id);
int gsm0480_wrap_facility(struct msgb *msg);

struct gsm48_hdr *gsm0480_l3hdr_push(struct msgb *msg, uint8_t proto_discr,
				     uint8_t msg_type);
