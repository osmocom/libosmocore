/* Serial communications layer, based on HDLC */

/* (C) 2010,2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/sercomm.h>

#ifdef HOST_BUILD

# define DEFAULT_RX_MSG_SIZE	2048
# ifndef ARRAY_SIZE
#  define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
# endif

static inline void sercomm_lock(unsigned long __attribute__((unused)) *flags) {}
static inline void sercomm_unlock(unsigned long __attribute__((unused)) *flags) {}

#else

# define DEFAULT_RX_MSG_SIZE	256
# include <debug.h>
# include <osmocom/core/linuxlist.h>
# include <asm/system.h>

static inline void sercomm_lock(unsigned long *flags)
{
	local_firq_save(*flags);
}

static inline void sercomm_unlock(unsigned long *flags)
{
	local_irq_restore(*flags);
}

# include <uart.h>

#endif

#define HDLC_FLAG	0x7E
#define HDLC_ESCAPE	0x7D

#define HDLC_C_UI	0x03
#define HDLC_C_P_BIT	(1 << 4)
#define HDLC_C_F_BIT	(1 << 4)

enum rx_state {
	RX_ST_WAIT_START,
	RX_ST_ADDR,
	RX_ST_CTRL,
	RX_ST_DATA,
	RX_ST_ESCAPE,
};


#ifndef HOST_BUILD
void osmo_sercomm_bind_uart(struct osmo_sercomm_inst *sercomm, int uart)
{
	sercomm->uart_id = uart;
}

int osmo_sercomm_get_uart(struct osmo_sercomm_inst *sercomm)
{
	return sercomm->uart_id;
}
#endif

void osmo_sercomm_init(struct osmo_sercomm_inst *sercomm)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(sercomm->tx.dlci_queues); i++)
		INIT_LLIST_HEAD(&sercomm->tx.dlci_queues[i]);

	sercomm->rx.msg = NULL;
	if (!sercomm->rx.msg_size)
		sercomm->rx.msg_size = DEFAULT_RX_MSG_SIZE;
	sercomm->initialized = 1;

	/* set up the echo dlci */
	osmo_sercomm_register_rx_cb(sercomm, SC_DLCI_ECHO, &osmo_sercomm_sendmsg);
}

int osmo_sercomm_initialized(struct osmo_sercomm_inst *sercomm)
{
	return sercomm->initialized;
}

/* user interface for transmitting messages for a given DLCI */
void osmo_sercomm_sendmsg(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg)
{
	unsigned long flags;
	uint8_t *hdr;

	/* prepend address + control octet */
	hdr = msgb_push(msg, 2);
	hdr[0] = dlci;
	hdr[1] = HDLC_C_UI;

	/* This functiion can be called from any context: FIQ, IRQ
	 * and supervisor context.  Proper locking is important! */
	sercomm_lock(&flags);
	msgb_enqueue(&sercomm->tx.dlci_queues[dlci], msg);
	sercomm_unlock(&flags);

#ifndef HOST_BUILD
	/* tell UART that we have something to send */
	uart_irq_enable(sercomm->uart_id, UART_IRQ_TX_EMPTY, 1);
#endif
}

/* how deep is the Tx queue for a given DLCI */
unsigned int osmo_sercomm_tx_queue_depth(struct osmo_sercomm_inst *sercomm, uint8_t dlci)
{
	struct llist_head *le;
	unsigned int num = 0;

	llist_for_each(le, &sercomm->tx.dlci_queues[dlci]) {
		num++;
	}

	return num;
}

#ifndef HOST_BUILD
/* wait until everything has been transmitted, then grab the lock and
 * change the baud rate as requested */
void osmo_sercomm_change_speed(struct osmo_sercomm_inst *sercomm, enum uart_baudrate bdrt)
{
	unsigned int i, count;
	unsigned long flags;

	while (1) {
		/* count the number of pending messages */
		count = 0;
		for (i = 0; i < ARRAY_SIZE(sercomm->tx.dlci_queues); i++)
			count += sercomm_tx_queue_depth(i);
		/* if we still have any in the queue, restart */
		if (count == 0)
			break;
	}

	while (1) {
		/* no messages in the queue, grab the lock to ensure it
		 * stays that way */
		sercomm_lock(&flags);
		if (!sercomm->tx.msg && !sercomm->tx.next_char) {
			/* change speed */
			uart_baudrate(sercomm->uart_id, bdrt);
			sercomm_unlock(&flags);
			break;
		}
			sercomm_unlock(&flags);
	}
}
#endif

/*! \brief fetch one octet of to-be-transmitted serial data
 *  \param[in] sercomm Sercomm Instance from which to fetch pending data
 *  \param[out] ch pointer to caller-allocaed output memory
 *  \returns 1 in case of succss; 0 if no data available; negative on error */
int osmo_sercomm_drv_pull(struct osmo_sercomm_inst *sercomm, uint8_t *ch)
{
	unsigned long flags;

	/* we may be called from interrupt context, but we stiff need to lock
	 * because sercomm could be accessed from a FIQ context ... */

	sercomm_lock(&flags);

	if (!sercomm->tx.msg) {
		unsigned int i;
		/* dequeue a new message from the queues */
		for (i = 0; i < ARRAY_SIZE(sercomm->tx.dlci_queues); i++) {
			sercomm->tx.msg = msgb_dequeue(&sercomm->tx.dlci_queues[i]);
			if (sercomm->tx.msg)
				break;
		}
		if (sercomm->tx.msg) {
			/* start of a new message, send start flag octet */
			*ch = HDLC_FLAG;
			sercomm->tx.next_char = sercomm->tx.msg->data;
			sercomm_unlock(&flags);
			return 1;
		} else {
			/* no more data avilable */
			sercomm_unlock(&flags);
			return 0;
		}
	}

	if (sercomm->tx.state == RX_ST_ESCAPE) {
		/* we've already transmitted the ESCAPE octet,
		 * we now need to transmit the escaped data */
		*ch = *sercomm->tx.next_char++;
		sercomm->tx.state = RX_ST_DATA;
	} else if (sercomm->tx.next_char >= sercomm->tx.msg->tail) {
		/* last character has already been transmitted,
		 * send end-of-message octet */
		*ch = HDLC_FLAG;
		/* we've reached the end of the message buffer */
		msgb_free(sercomm->tx.msg);
		sercomm->tx.msg = NULL;
		sercomm->tx.next_char = NULL;
	/* escaping for the two control octets */
	} else if (*sercomm->tx.next_char == HDLC_FLAG ||
		   *sercomm->tx.next_char == HDLC_ESCAPE ||
		   *sercomm->tx.next_char == 0x00) {
		/* send an escape octet */
		*ch = HDLC_ESCAPE;
		/* invert bit 5 of the next octet to be sent */
		*sercomm->tx.next_char ^= (1 << 5);
		sercomm->tx.state = RX_ST_ESCAPE;
	} else {
		/* standard case, simply send next octet */
		*ch = *sercomm->tx.next_char++;
	}

	sercomm_unlock(&flags);
	return 1;
}

/*! \brief Register a handler for a given DLCI
 *  \param sercomm Sercomm Instance in which caller wishes to register
 *  \param[in] dlci Data Ling Connection Identifier to register
 *  \param[in] cb Callback function for \a dlci
 *  \returns 0 on success; negative on error */
int osmo_sercomm_register_rx_cb(struct osmo_sercomm_inst *sercomm, uint8_t dlci, dlci_cb_t cb)
{
	if (dlci >= ARRAY_SIZE(sercomm->rx.dlci_handler))
		return -EINVAL;

	if (sercomm->rx.dlci_handler[dlci])
		return -EBUSY;

	sercomm->rx.dlci_handler[dlci] = cb;
	return 0;
}

/* dispatch an incoming message once it is completely received */
static void dispatch_rx_msg(struct osmo_sercomm_inst *sercomm, uint8_t dlci, struct msgb *msg)
{
	if (dlci >= ARRAY_SIZE(sercomm->rx.dlci_handler) ||
	    !sercomm->rx.dlci_handler[dlci]) {
		msgb_free(msg);
		return;
	}
	sercomm->rx.dlci_handler[dlci](sercomm, dlci, msg);
}

/*! \brief the driver has received one byte, pass it into sercomm layer
 *  \param[in] sercomm Sercomm Instance for which a byte was received
 *  \param[in] ch byte that was received from line for said instance
 *  \returns 1 on success; 0 on unrecognized char; negative on error */
int osmo_sercomm_drv_rx_char(struct osmo_sercomm_inst *sercomm, uint8_t ch)
{
	uint8_t *ptr;

	/* we are always called from interrupt context in this function,
	 * which means that any data structures we use need to be for
	 * our exclusive access */
	if (!sercomm->rx.msg)
		sercomm->rx.msg = osmo_sercomm_alloc_msgb(sercomm->rx.msg_size);

	if (msgb_tailroom(sercomm->rx.msg) == 0) {
		//cons_puts("sercomm_drv_rx_char() overflow!\n");
		msgb_free(sercomm->rx.msg);
		sercomm->rx.msg = osmo_sercomm_alloc_msgb(sercomm->rx.msg_size);
		sercomm->rx.state = RX_ST_WAIT_START;
		return 0;
	}

	switch (sercomm->rx.state) {
	case RX_ST_WAIT_START:
		if (ch != HDLC_FLAG)
			break;
		sercomm->rx.state = RX_ST_ADDR;
		break;
	case RX_ST_ADDR:
		sercomm->rx.dlci = ch;
		sercomm->rx.state = RX_ST_CTRL;
		break;
	case RX_ST_CTRL:
		sercomm->rx.ctrl = ch;
		sercomm->rx.state = RX_ST_DATA;
		break;
	case RX_ST_DATA:
		if (ch == HDLC_ESCAPE) {
			/* drop the escape octet, but change state */
			sercomm->rx.state = RX_ST_ESCAPE;
			break;
		} else if (ch == HDLC_FLAG) {
			/* message is finished */
			dispatch_rx_msg(sercomm, sercomm->rx.dlci, sercomm->rx.msg);
			/* allocate new buffer */
			sercomm->rx.msg = NULL;
			/* start all over again */
			sercomm->rx.state = RX_ST_WAIT_START;

			/* do not add the control char */
			break;
		}
		/* default case: store the octet */
		ptr = msgb_put(sercomm->rx.msg, 1);
		*ptr = ch;
		break;
	case RX_ST_ESCAPE:
		/* store bif-5-inverted octet in buffer */
		ch ^= (1 << 5);
		ptr = msgb_put(sercomm->rx.msg, 1);
		*ptr = ch;
		/* transition back to normal DATA state */
		sercomm->rx.state = RX_ST_DATA;
		break;
	}

	return 1;
}
