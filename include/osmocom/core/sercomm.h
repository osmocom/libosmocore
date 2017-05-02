#ifndef _SERCOMM_H
#define _SERCOMM_H

#include <osmocom/core/msgb.h>

/* a low sercomm_dlci means high priority.  A high DLCI means low priority */
enum sercomm_dlci {
	SC_DLCI_HIGHEST = 0,
	SC_DLCI_DEBUG   = 4,
	SC_DLCI_L1A_L23 = 5,
	SC_DLCI_LOADER  = 9,
	SC_DLCI_CONSOLE = 10,
	SC_DLCI_ECHO    = 128,
	_SC_DLCI_MAX
};

struct osmo_sercomm_inst;
/*! \brief call-back function for per-DLC receive handler
 *  \param[in] sercomm instance on which msg was received
 *  \param[in] dlci DLC Identifier of received msg
 *  \param[in] msg received message that needs to be processed */
typedef void (*dlci_cb_t)(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg);

/*! \brief one instance of a sercomm multiplex/demultiplex */
struct osmo_sercomm_inst {
	/*! \brief Has this instance been initialized? */
	int initialized;
	/*! \brief UART Identifier */
	int uart_id;

	/*! \brief transmit side */
	struct {
		/*! \brief per-DLC queue of pending transmit msgbs */
		struct llist_head dlci_queues[_SC_DLCI_MAX];
		/*! \brief msgb currently being transmitted */
		struct msgb *msg;
		/*! \brief transmit state */
		int state;
		/*! \brief next to-be-transmitted char in msg */
		uint8_t *next_char;
	} tx;

	/*! \brief receive side */
	struct {
		/*! \brief per-DLC handler call-back functions */
		dlci_cb_t dlci_handler[_SC_DLCI_MAX];
		/*! \brief msgb allocation size for rx msgs */
		unsigned int msg_size;
		/*! \brief currently received msgb */
		struct msgb *msg;
		/*! \brief receive state */
		int state;
		/*! \brief DLCI of currently received msgb */
		uint8_t dlci;
		/*! \brief CTRL of currently received msgb */
		uint8_t ctrl;
	} rx;
};


#ifndef HOST_BUILD
#include <uart.h>
/* helper functions for target */
void osmo_sercomm_bind_uart(struct osmo_sercomm_inst *sercomm, int uart);
int osmo_sercomm_get_uart(struct osmo_sercomm_inst *sercomm);
void osmo_sercomm_change_speed(struct osmo_sercomm_inst *sercomm, enum uart_baudrate bdrt);
#endif

void osmo_sercomm_init(struct osmo_sercomm_inst *sercomm);
int osmo_sercomm_initialized(struct osmo_sercomm_inst *sercomm);

/* User Interface: Tx */
void osmo_sercomm_sendmsg(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg);
unsigned int osmo_sercomm_tx_queue_depth(struct osmo_sercomm_inst *sercomm, uint8_t dlci);

/* User Interface: Rx */
int osmo_sercomm_register_rx_cb(struct osmo_sercomm_inst *sercomm, uint8_t dlci, dlci_cb_t cb);

/* Driver Interface */

int osmo_sercomm_drv_pull(struct osmo_sercomm_inst *sercomm, uint8_t *ch);
int osmo_sercomm_drv_rx_char(struct osmo_sercomm_inst *sercomm, uint8_t ch);

static inline struct msgb *osmo_sercomm_alloc_msgb(unsigned int len)
{
	return msgb_alloc_headroom(len+4, 4, "sercomm_tx");
}

#endif /* _SERCOMM_H */
