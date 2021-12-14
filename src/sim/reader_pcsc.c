/*! \file reader_pcsc.c
 * PC/SC Card reader backend for libosmosim. */
/*
 * (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 */


#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/sim/sim.h>

#include <wintypes.h>
#include <winscard.h>

#include "sim_int.h"

#define PCSC_ERROR(rv, text) \
if (rv != SCARD_S_SUCCESS) { \
	fprintf(stderr, text ": %s (0x%lX)\n", pcsc_stringify_error(rv), rv); \
	goto end; \
}


struct pcsc_reader_state {
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	DWORD dwActiveProtocol;
	const SCARD_IO_REQUEST *pioSendPci;
	SCARD_IO_REQUEST pioRecvPci;
	char *name;
};

static int pcsc_get_atr(struct osim_card_hdl *card)
{
	struct osim_reader_hdl *rh = card->reader;
	struct pcsc_reader_state *st = rh->priv;
	char pbReader[MAX_READERNAME];
	DWORD dwReaderLen = sizeof(pbReader);
	DWORD dwAtrLen = sizeof(card->atr);
	DWORD dwState, dwProt;
	long rc;

	rc = SCardStatus(st->hCard, pbReader, &dwReaderLen, &dwState, &dwProt,
			 card->atr, &dwAtrLen);
	PCSC_ERROR(rc, "SCardStatus");
	card->atr_len = dwAtrLen;

	return 0;

end:
	return -EIO;
}

static struct osim_reader_hdl *pcsc_reader_open(int num, const char *id, void *ctx)
{
	struct osim_reader_hdl *rh;
	struct pcsc_reader_state *st;
	LONG rc;
	LPSTR mszReaders = NULL;
	DWORD dwReaders;
	unsigned int num_readers;
	char *ptr;

	/* FIXME: implement matching on id or num */

	rh = talloc_zero(ctx, struct osim_reader_hdl);
	st = rh->priv = talloc_zero(rh, struct pcsc_reader_state);

	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
				   &st->hContext);
	PCSC_ERROR(rc, "SCardEstablishContext");

	dwReaders = SCARD_AUTOALLOCATE;
	rc = SCardListReaders(st->hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
	PCSC_ERROR(rc, "SCardListReaders");

	/* SCARD_S_SUCCESS means there is at least one reader in the group */
	num_readers = 0;
	ptr = mszReaders;
	while (*ptr != '\0' && num_readers != num) {
		ptr += strlen(ptr)+1;
		num_readers++;
	}

	if (num != num_readers) {
		SCardFreeMemory(st->hContext, mszReaders);
		goto end;
	}

	st->name = talloc_strdup(rh, ptr);
	st->dwActiveProtocol = -1;
	SCardFreeMemory(st->hContext, mszReaders);

	return rh;
end:
	talloc_free(rh);
	return NULL;
}

static struct osim_card_hdl *pcsc_card_open(struct osim_reader_hdl *rh,
					    enum osim_proto proto)
{
	struct pcsc_reader_state *st = rh->priv;
	struct osim_card_hdl *card;
	struct osim_chan_hdl *chan;
	LONG rc;

	if (proto != OSIM_PROTO_T0)
		return NULL;

	rc = SCardConnect(st->hContext, st->name, SCARD_SHARE_SHARED,
			  SCARD_PROTOCOL_T0, &st->hCard, &st->dwActiveProtocol);
	PCSC_ERROR(rc, "SCardConnect");

	st->pioSendPci = SCARD_PCI_T0;

	card = talloc_zero(rh, struct osim_card_hdl);
	INIT_LLIST_HEAD(&card->channels);
	INIT_LLIST_HEAD(&card->apps);
	card->reader = rh;
	rh->card = card;

	/* create a default channel */
	chan = talloc_zero(card, struct osim_chan_hdl);
	chan->card = card;
	llist_add(&chan->list, &card->channels);

	pcsc_get_atr(card);

	return card;

end:
	return NULL;
}

static int pcsc_card_reset(struct osim_card_hdl *card, bool cold_reset)
{
	struct pcsc_reader_state *st = card->reader->priv;
	LONG rc;

	rc = SCardReconnect(st->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0,
			    cold_reset ? SCARD_UNPOWER_CARD : SCARD_RESET_CARD,
			    &st->dwActiveProtocol);
	PCSC_ERROR(rc, "SCardReconnect");

	return 0;
end:
	return -EIO;
}

static int pcsc_card_close(struct osim_card_hdl *card)
{
	struct pcsc_reader_state *st = card->reader->priv;
	LONG rc;

	rc = SCardDisconnect(st->hCard, SCARD_UNPOWER_CARD);
	PCSC_ERROR(rc, "SCardDisconnect");

	return 0;
end:
	return -EIO;
}


static int pcsc_transceive(struct osim_reader_hdl *rh, struct msgb *msg)
{
	struct pcsc_reader_state *st = rh->priv;
	DWORD rlen = msgb_tailroom(msg);
	LONG rc;

	rc = SCardTransmit(st->hCard, st->pioSendPci, msg->data, msgb_length(msg),
			   &st->pioRecvPci, msg->tail, &rlen);
	PCSC_ERROR(rc, "SCardEndTransaction");

	msgb_put(msg, rlen);
	msgb_apdu_le(msg) = rlen;

	return 0;
end:
	return -EIO;
}

const struct osim_reader_ops pcsc_reader_ops = {
	.name = "PC/SC",
	.reader_open = pcsc_reader_open,
	.card_open = pcsc_card_open,
	.card_reset = pcsc_card_reset,
	.card_close = pcsc_card_close,
	.transceive = pcsc_transceive,
};

