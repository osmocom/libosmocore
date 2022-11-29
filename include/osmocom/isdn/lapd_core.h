/*! \file lapd_core.h
 * primitive related stuff
 */
#pragma once

#include <stdint.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/prim.h>

/*! \defgroup lapd LAPD implementation common part
 *  @{
 * \file lapd_core.h
 */

#define LOGDL(dl, level, fmt, args...) \
	LOGP(DLLAPD, level, "(%s) "  fmt, (dl)->name, ## args)

/*! LAPD related primitives (L2<->L3 SAP)*/
enum osmo_dl_prim {
	PRIM_DL_UNIT_DATA,	/*!< DL-UNIT-DATA */
	PRIM_DL_DATA,		/*!< DL-DATA */
	PRIM_DL_EST,		/*!< DL-ESTABLISH */
	PRIM_DL_REL,		/*!< DL-RLEEASE */
	PRIM_DL_SUSP,		/*!< DL-SUSPEND */
	PRIM_DL_RES,		/*!< DL-RESUME */
	PRIM_DL_RECON,		/*!< DL-RECONNECT */
	PRIM_MDL_ERROR,		/*!< MDL-ERROR */
};

/* Uses the same values as RLL, so no conversion for GSM is required. */
#define MDL_CAUSE_T200_EXPIRED		0x01
#define MDL_CAUSE_REEST_REQ		0x02
#define MDL_CAUSE_UNSOL_UA_RESP		0x03
#define MDL_CAUSE_UNSOL_DM_RESP		0x04
#define MDL_CAUSE_UNSOL_DM_RESP_MF	0x05
#define MDL_CAUSE_UNSOL_SPRV_RESP	0x06
#define MDL_CAUSE_SEQ_ERR		0x07
#define MDL_CAUSE_UFRM_INC_PARAM	0x08
#define MDL_CAUSE_SFRM_INC_PARAM	0x09
#define MDL_CAUSE_IFRM_INC_MBITS	0x0a
#define MDL_CAUSE_IFRM_INC_LEN		0x0b
#define MDL_CAUSE_FRM_UNIMPL		0x0c
#define MDL_CAUSE_SABM_MF		0x0d
#define MDL_CAUSE_SABM_INFO_NOTALL	0x0e
#define MDL_CAUSE_FRMR			0x0f

/*! for MDL-ERROR.ind */
struct mdl_error_ind_param {
	uint8_t cause;		/*!< generic cause value */
};

/*! for DL-REL.req */
struct dl_rel_req_param {
	uint8_t mode;		/*!< release mode */
};

/*! primitive header for LAPD DL-SAP primitives */
struct osmo_dlsap_prim {
	struct osmo_prim_hdr oph; /*!< generic primitive header */
	union {
		struct mdl_error_ind_param error_ind;
		struct dl_rel_req_param rel_req;
	} u;			/*!< request-specific data */
};

/*! LAPD mode/role */
enum lapd_mode {
	LAPD_MODE_USER,		/*!< behave like user */
	LAPD_MODE_NETWORK,	/*!< behave like network */
};

/*! LAPD state (Figure B.2/Q.921)*/
enum lapd_state {
	LAPD_STATE_NULL = 0,
	LAPD_STATE_TEI_UNASS,
	LAPD_STATE_ASS_TEI_WAIT,
	LAPD_STATE_EST_TEI_WAIT,
	LAPD_STATE_IDLE,
	LAPD_STATE_SABM_SENT,
	LAPD_STATE_DISC_SENT,
	LAPD_STATE_MF_EST,
	LAPD_STATE_TIMER_RECOV,
};

/*! LAPD message format (I / S / U) */
enum lapd_format {
	LAPD_FORM_UKN = 0,
	LAPD_FORM_I,
	LAPD_FORM_S,
	LAPD_FORM_U,
};

/*! LAPD message context */
struct lapd_msg_ctx {
	struct lapd_datalink *dl;
	int n201;
	/* address */
	uint8_t cr;
	uint8_t sapi;
	uint8_t tei;
	uint8_t lpd;
	/* control */
	uint8_t format;
	uint8_t p_f; /* poll / final bit */
	uint8_t n_send;
	uint8_t n_recv;
	uint8_t s_u; /* S or repectivly U function bits */
	/* length */
	int	length;
	uint8_t	more;
};

struct lapd_cr_ent {
	uint8_t cmd;
	uint8_t resp;
};

struct lapd_history {
	struct msgb *msg; /* message to be sent / NULL, if histoy is empty */
	int	more; /* if message is fragmented */
};

/*! LAPD datalink */
struct lapd_datalink {
	int (*send_dlsap)(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx);
	int (*send_ph_data_req)(struct lapd_msg_ctx *lctx, struct msgb *msg);
	int (*update_pending_frames)(struct lapd_msg_ctx *lctx);
	struct {
		/*! filled-in once we set the lapd_mode above */
		struct lapd_cr_ent loc2rem;
		struct lapd_cr_ent rem2loc;
	} cr;
	enum lapd_mode mode; /*!< current mode of link */
	int use_sabme; /*!< use SABME instead of SABM */
	int reestablish; /*!< enable reestablish support */
	int n200, n200_est_rel; /*!< number of retranmissions */
	struct lapd_msg_ctx lctx; /*!< LAPD context */
	int maxf; /*!< maximum frame size (after defragmentation) */
	uint8_t k; /*!< maximum number of unacknowledged frames */
	uint8_t v_range; /*!< range of sequence numbers */
	uint8_t v_send;	/*!< seq nr of next I frame to be transmitted */
	uint8_t v_ack;	/*!< last frame ACKed by peer */
	uint8_t v_recv;	/*!< seq nr of next I frame expected to be received */
	uint32_t state; /*!< LAPD state (\ref lapd_state) */
	int seq_err_cond; /*!< condition of sequence error */
	uint8_t own_busy; /*!< receiver busy on our side */
	uint8_t peer_busy; /*!< receiver busy on remote side */
	int t200_sec, t200_usec; /*!< retry timer (default 1 sec) */
	int t203_sec, t203_usec; /*!< retry timer (default 10 secs) */
	struct osmo_timer_list t200; /*!< T200 timer */
	struct osmo_timer_list t203; /*!< T203 timer */
	uint8_t retrans_ctr; /*!< re-transmission counter */
	struct llist_head tx_queue; /*!< frames to L1 */
	struct llist_head send_queue; /*!< frames from L3 */
	struct msgb *send_buffer; /*!< current frame transmitting */
	int send_out; /*!< how much was sent from send_buffer */
	struct lapd_history *tx_hist; /*!< tx history structure array */
	uint8_t range_hist; /*!< range of history buffer 2..2^n */
	struct msgb *rcv_buffer; /*!< buffer to assemble the received message */
	struct msgb *cont_res; /*!< buffer to store content resolution data on network side, to detect multiple phones on same channel */
	char *name; /*!< user-provided name */
};

void lapd_dl_init(struct lapd_datalink *dl, uint8_t k, uint8_t v_range, int maxf)
	OSMO_DEPRECATED("Use lapd_dl_init2() instead");
void lapd_dl_init2(struct lapd_datalink *dl, uint8_t k, uint8_t v_range, int maxf, const char *name);
void lapd_dl_set_name(struct lapd_datalink *dl, const char *name);
void lapd_dl_exit(struct lapd_datalink *dl);
void lapd_dl_reset(struct lapd_datalink *dl);
int lapd_set_mode(struct lapd_datalink *dl, enum lapd_mode mode);
int lapd_ph_data_ind(struct msgb *msg, struct lapd_msg_ctx *lctx);
int lapd_recv_dlsap(struct osmo_dlsap_prim *dp, struct lapd_msg_ctx *lctx);

/*! @} */
