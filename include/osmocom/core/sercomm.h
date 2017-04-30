#ifndef _SERCOMM_H
#define _SERCOMM_H

#include <osmocom/core/msgb.h>

#define HDLC_FLAG	0x7E
#define HDLC_ESCAPE	0x7D

#define HDLC_C_UI	0x03
#define HDLC_C_P_BIT	(1 << 4)
#define HDLC_C_F_BIT	(1 << 4)

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
typedef void (*dlci_cb_t)(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg);

struct osmo_sercomm_inst {
	int initialized;
	int uart_id;

	/* transmit side */
	struct {
		struct llist_head dlci_queues[_SC_DLCI_MAX];
		struct msgb *msg;
		int state;
		uint8_t *next_char;
	} tx;

	/* receive side */
	struct {
		dlci_cb_t dlci_handler[_SC_DLCI_MAX];
		struct msgb *msg;
		int state;
		uint8_t dlci;
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

/* user interface for transmitting messages for a given DLCI */
void osmo_sercomm_sendmsg(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg);
/* how deep is the Tx queue for a given DLCI */
unsigned int osmo_sercomm_tx_queue_depth(struct osmo_sercomm_inst *sercomm, uint8_t dlci);

/* User Interface: Rx */

/* receiving messages for a given DLCI */
int osmo_sercomm_register_rx_cb(struct osmo_sercomm_inst *sercomm, uint8_t dlci, dlci_cb_t cb);

/* Driver Interface */

/* fetch one octet of to-be-transmitted serial data. returns 0 if no more data */
int osmo_sercomm_drv_pull(struct osmo_sercomm_inst *sercomm, uint8_t *ch);
/* the driver has received one byte, pass it into sercomm layer.
   returns 1 in case of success, 0 in case of unrecognized char */
int osmo_sercomm_drv_rx_char(struct osmo_sercomm_inst *sercomm, uint8_t ch);

static inline struct msgb *osmo_sercomm_alloc_msgb(unsigned int len)
{
	return msgb_alloc_headroom(len+4, 4, "sercomm_tx");
}

#endif /* _SERCOMM_H */
