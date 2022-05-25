#pragma once

#include <stdint.h>

#include <osmocom/core/prim.h>
#include <osmocom/gsm/protocol/gsm_25_415.h>

/***********************************************************************
 * Primitives towards the lower layers (typically RTP transport)
 ***********************************************************************/
enum osmo_iuup_tnl_prim_type {
	OSMO_IUUP_TNL_UNITDATA,
};

struct osmo_iuup_tnl_prim {
	struct osmo_prim_hdr oph;
};

/***********************************************************************
 * Primitives towards the upper layers at the RNL SAP
 ***********************************************************************/

/* 3GPP TS 25.415 Section 7.2.1 */
enum osmo_iuup_rnl_prim_type {
	OSMO_IUUP_RNL_CONFIG,
	OSMO_IUUP_RNL_DATA,
	OSMO_IUUP_RNL_STATUS,
	OSMO_IUUP_RNL_UNIT_DATA,
};

/* TS 25.413 9.2.1.3*/
#define IUUP_MAX_SUBFLOWS 7
#define IUUP_MAX_RFCIS 64

#define IUUP_TIMER_INIT_T_DEFAULT 1000
#define IUUP_TIMER_TA_T_DEFAULT 500
#define IUUP_TIMER_RC_T_DEFAULT 500
#define IUUP_TIMER_INIT_N_DEFAULT 3
#define IUUP_TIMER_TA_N_DEFAULT 1
#define IUUP_TIMER_RC_N_DEFAULT 1
struct osmo_iuup_rnl_config_timer {
	uint32_t t_ms;	/* time in ms */
	uint32_t n_max;	/* max number of repetitions */
};
struct osmo_iuup_rfci {
	uint8_t used:1,
		spare1:1,
		id:6;
	uint8_t spare2:4,
		IPTI:4; /* values range 0-15, 4 bits */;
	uint16_t subflow_sizes[IUUP_MAX_SUBFLOWS];
};
struct osmo_iuup_rnl_config {
	/* transparent (true) or SMpSDU (false): */
	bool transparent;

	/* should we actively transmit INIT in SmpSDU mode? */
	bool active;

	/* Currently Version 0 or 1: */
	uint8_t data_pdu_type;

	/* Supported mode versions */
	uint16_t supported_versions_mask;
	uint8_t num_rfci;
	uint8_t num_subflows;
	bool IPTIs_present;
	struct osmo_iuup_rfci rfci[IUUP_MAX_RFCIS];

	/* TODO: Indication of delivery of erroneous SDUs*/
	struct osmo_iuup_rnl_config_timer t_init;
	struct osmo_iuup_rnl_config_timer t_ta;
	struct osmo_iuup_rnl_config_timer t_rc;
};

struct osmo_iuup_rnl_data {
	uint8_t rfci;
	uint8_t frame_nr;
	uint8_t fqc;
};

struct osmo_iuup_rnl_status {
	enum iuup_procedure procedure;
	union {
		struct {
			enum iuup_error_cause cause;
			enum iuup_error_distance distance;
		} error_event;
		struct {
			uint16_t mode_version;
			uint8_t data_pdu_type;
			uint8_t num_rfci;
			uint8_t num_subflows;
			bool IPTIs_present;
			struct osmo_iuup_rfci rfci[IUUP_MAX_RFCIS];
		} initialization;
		struct {
		} rate_control;
		struct {
		} time_alignment;
	} u;
};

/* SAP on the upper side of IuUP, towards the user */
struct osmo_iuup_rnl_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_iuup_rnl_config config;
		struct osmo_iuup_rnl_data data;
		struct osmo_iuup_rnl_status status;
		//struct osmo_iuup_rnl_unitdata unitdata;
	} u;
};

struct osmo_iuup_instance;
struct osmo_iuup_instance *osmo_iuup_instance_alloc(void *ctx, const char *id);
void osmo_iuup_instance_free(struct osmo_iuup_instance *iui);

void osmo_iuup_instance_set_user_prim_cb(struct osmo_iuup_instance *iui, osmo_prim_cb func, void *priv);
void osmo_iuup_instance_set_transport_prim_cb(struct osmo_iuup_instance *iui, osmo_prim_cb func, void *priv);
int osmo_iuup_tnl_prim_up(struct osmo_iuup_instance *iui, struct osmo_iuup_tnl_prim *itp);
int osmo_iuup_rnl_prim_down(struct osmo_iuup_instance *inst, struct osmo_iuup_rnl_prim *irp);


int osmo_iuup_compute_header_crc(const uint8_t *iuup_pdu, unsigned int pdu_len);
int osmo_iuup_compute_payload_crc(const uint8_t *iuup_pdu, unsigned int pdu_len);

struct osmo_iuup_rnl_prim *osmo_iuup_rnl_prim_alloc(void *ctx, unsigned int primitive, unsigned int operation, unsigned int size);
struct osmo_iuup_tnl_prim *osmo_iuup_tnl_prim_alloc(void *ctx, unsigned int primitive, unsigned int operation, unsigned int size);
