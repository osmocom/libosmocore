#pragma once

#include <osmocom/core/defs.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>

#define MAX_LEN_USSD_STRING	182

/* deprecated */
struct ussd_request {
	char text[MAX_LEN_USSD_STRING + 1];
	uint8_t transaction_id;
	uint8_t invoke_id;
};

/* deprecated */
int gsm0480_decode_ussd_request(const struct gsm48_hdr *hdr, uint16_t len,
				struct ussd_request *request) OSMO_DEPRECATED("Use gsm0480_decode_ss_request() instead");

struct ss_request {
	uint8_t transaction_id; /**< L3 transaction ID */
	uint8_t message_type;   /**< Message type        2.2   */

	uint8_t component_type; /**< Component type      3.6.2 */
	uint8_t invoke_id;      /**< Invoke id           3.6.3 */

	union {
		uint8_t opcode;         /**< Operational code    3.6.4 */
		uint8_t error_code;     /**< Error code          3.6.6 */
		uint8_t problem_code;   /**< Problem code        3.6.7 */
	};

	uint8_t ussd_text_len;
	uint8_t ussd_text_language;
	uint8_t ussd_text[MAX_LEN_USSD_STRING + 1];

	uint8_t ss_code;       /**< parameters of a Interrogate/Activate/DeactivateSS Request */
};
int gsm0480_decode_ss_request(const struct gsm48_hdr *hdr, uint16_t len,
				struct ss_request *request);

struct msgb *gsm0480_create_ussd_resp(uint8_t invoke_id, uint8_t trans_id, const char *text);
struct msgb *gsm0480_create_unstructuredSS_Notify(int alertPattern, const char *text);
struct msgb *gsm0480_create_notifySS(const char *text);
struct msgb *gsm0480_create_ussd_notify(int level, const char *text);
struct msgb *gsm0480_create_ussd_release_complete(void);

int gsm0480_wrap_invoke(struct msgb *msg, int op, int link_id);
int gsm0480_wrap_facility(struct msgb *msg);

struct gsm48_hdr *gsm0480_l3hdr_push(struct msgb *msg, uint8_t proto_discr,
				     uint8_t msg_type);
