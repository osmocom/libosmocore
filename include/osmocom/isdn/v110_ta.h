#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/isdn/v110.h>

/* Definition of this struct is [intentionally] kept private */
struct osmo_v110_ta;

/*! V.110 5.4.1 Local flow control (DTE-DCE or TE-TA) mode */
enum osmo_v110_local_flow_ctrl_mode {
	OSMO_V110_LOCAL_FLOW_CTRL_NONE,		/*!< No local flow control */
	OSMO_V110_LOCAL_FLOW_CTRL_133_106,	/*!< 5.4.1.1 133/106 operation */
	OSMO_V110_LOCAL_FLOW_CTRL_105_106,	/*!< 5.4.1.2 105/106 operation */
	OSMO_V110_LOCAL_FLOW_CTRL_XON_XOFF,	/*!< 5.4.1.3 XON/XOFF operation */
};

/*! Configuration for a V.110 TA instance */
struct osmo_v110_ta_cfg {
	/*! Configuration flags (behavior switches and quirks) */
	unsigned int flags;
	/*! Synchronous user rate */
	enum osmo_v100_sync_ra1_rate rate;

	/*! Flow control configuration */
	struct {
		/*! Local TA-TE (DTE-DCE) flow control mode */
		enum osmo_v110_local_flow_ctrl_mode local;
		/*! End-to-end (TA-to-TA) flow control state */
		bool end_to_end;
	} flow_ctrl;

	/*! Opaque application-private data; passed to call-backs. */
	void *priv;

	/*! Receive call-back of the application.
	 * \param[in] priv opaque application-private data.
	 * \param[in] buf output buffer for writing to be transmitted data.
	 * \param[in] buf_size size of the output buffer. */
	void (*rx_cb)(void *priv, const ubit_t *buf, size_t buf_size);

	/*! Transmit call-back of the application.
	 * \param[in] priv opaque application-private data.
	 * \param[out] buf output buffer for writing to be transmitted data.
	 * \param[in] buf_size size of the output buffer. */
	void (*tx_cb)(void *priv, ubit_t *buf, size_t buf_size);

	/*! Modem status line update call-back (optional).
	 * \param[in] priv opaque application-private data.
	 * \param[in] status updated status; bit-mask of OSMO_V110_TA_C_*. */
	void (*status_update_cb)(void *priv, unsigned int status);
};

struct osmo_v110_ta *osmo_v110_ta_alloc(void *ctx, const char *name,
					const struct osmo_v110_ta_cfg *cfg);
void osmo_v110_ta_free(struct osmo_v110_ta *ta);

/*! Various timers for a V.110 TA instance */
enum osmo_v110_ta_timer {
	/*! 7.1.5 Loss of frame synchronization: sync recovery timer.
	 * T-number is not assigned in V.110, so we call it X1. */
	OSMO_V110_TA_TIMER_X1		= -1,
	/*! 7.1.2 Connect TA to line: sync establishment timer */
	OSMO_V110_TA_TIMER_T1		= 1,
	/*! 7.1.4 Disconnect mode: disconnect confirmation timer */
	OSMO_V110_TA_TIMER_T2		= 2,
};

int osmo_v110_ta_set_timer_val_ms(struct osmo_v110_ta *ta,
				  enum osmo_v110_ta_timer timer,
				  unsigned long val_ms);

int osmo_v110_ta_frame_in(struct osmo_v110_ta *ta, const struct osmo_v110_decoded_frame *in);
int osmo_v110_ta_frame_out(struct osmo_v110_ta *ta, struct osmo_v110_decoded_frame *out);

int osmo_v110_ta_sync_ind(struct osmo_v110_ta *ta);
int osmo_v110_ta_desync_ind(struct osmo_v110_ta *ta);

/*! ITU-T Table 9 "Interchange circuit" (see also ITU-T V.24 Chapter 3).
 * XXX: Not all circuits are present here, only those which we actually use.
 * TODO: add human-friendly abbreviated circuit names. */
enum osmo_v110_ta_circuit {
	OSMO_V110_TA_C_105,		/*!< DTE->DCE | RTS (Request to Send) */
	OSMO_V110_TA_C_106,		/*!< DTE<-DCE | CTS (Clear to Send) */
	OSMO_V110_TA_C_107,		/*!< DTE<-DCE | DSR (Data Set Ready) */
	OSMO_V110_TA_C_108,		/*!< DTE->DCE | DTR (Data Terminal Ready) */
	OSMO_V110_TA_C_109,		/*!< DTE<-DCE | DCD (Data Carrier Detect) */
	OSMO_V110_TA_C_133,		/*!< DTE->DCE | Ready for receiving */
};

extern const struct value_string osmo_v110_ta_circuit_names[];
extern const struct value_string osmo_v110_ta_circuit_descs[];

/*! Get a short name of the given TA's circuit (format: NNN[/ABBR]). */
static inline const char *osmo_v110_ta_circuit_name(enum osmo_v110_ta_circuit circuit)
{
	return get_value_string(osmo_v110_ta_circuit_names, circuit);
}

/*! Get a brief description of the given TA's circuit. */
static inline const char *osmo_v110_ta_circuit_desc(enum osmo_v110_ta_circuit circuit)
{
	return get_value_string(osmo_v110_ta_circuit_descs, circuit);
}

unsigned int osmo_v110_ta_get_status(const struct osmo_v110_ta *ta);
bool osmo_v110_ta_get_circuit(const struct osmo_v110_ta *ta,
			      enum osmo_v110_ta_circuit circuit);
int osmo_v110_ta_set_circuit(struct osmo_v110_ta *ta,
			     enum osmo_v110_ta_circuit circuit, bool active);
