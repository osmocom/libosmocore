#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/isdn/v110.h>
#include <osmocom/core/soft_uart.h>
#include <osmocom/trau/trau_sync.h>
#include <osmocom/gsm/i460_mux.h>

static struct osmo_i460_timeslot g_i460_ts;
static struct osmo_fsm_inst *g_sync_fi;
static struct osmo_soft_uart *g_suart;

typedef void (*process_cb)(const uint8_t *buf, size_t buf_len);

static int open_and_process(const char *fname, const process_cb *cb)
{
	int fd = open(fname, O_RDONLY);
	uint8_t buf[80];

	if (fd < 0)
		return fd;

	while (true) {
		int rc = read(fd, buf, sizeof(buf));
		if (rc <= 0)
			return rc;
		/* feed into I.460 de-multiplexer (for 64/32/16/8k rate) */
		osmo_i460_demux_in(&g_i460_ts, buf, rc);
	}
}

static void i460_out_bits_cb(struct osmo_i460_subchan *schan, void *user_data,
			     const ubit_t *bits, unsigned int num_bits)
{
	/* feed 8/16/32/64k stream into frame sync */
	osmo_trau_sync_rx_ubits(g_sync_fi, bits, num_bits);
}

/* call-back for each synced V.110 frame */
static void frame_bits_cb(void *user_data, const ubit_t *bits, unsigned int num_bits)
{
	struct osmo_v110_decoded_frame dfr;
	int rc;

	/* dump the bits of each V.110 frame */
	//printf("%s\n", osmo_ubit_dump(bits, num_bits));
	rc = osmo_v110_decode_frame(&dfr, bits, num_bits);
	if (rc < 0) {
		printf("\tERROR decoding V.110 frame\n");
		return;
	}
#if 0
	printf("\tS: %s\n", osmo_ubit_dump(dfr.s_bits, sizeof(dfr.s_bits)));
	printf("\tX: %s\n", osmo_ubit_dump(dfr.x_bits, sizeof(dfr.x_bits)));
	printf("\tE: %s\n", osmo_ubit_dump(dfr.e_bits, sizeof(dfr.e_bits)));
	printf("\tD: %s\n", osmo_ubit_dump(dfr.d_bits, sizeof(dfr.d_bits)));
#endif

	osmo_soft_uart_rx_ubits(g_suart, dfr.d_bits, sizeof(dfr.d_bits));
}

static void uart_rx_cb(void *priv, struct msgb *rx_data, unsigned int flags)
{
	char *data = (char *) msgb_data(rx_data);

	for (unsigned int i = 0; i < msgb_length(rx_data); i++) {
		fputc(data[i], stdout);
		if (data[i] == '\r')
			fputc('\n', stdout);
	}

	if (flags)
		fprintf(stderr, "UART FLAGS: 0x%08x\n", flags);

	msgb_free(rx_data);
}

static struct osmo_i460_schan_desc g_i460_chd = {
	//TODO: this must be adjustable to 8/16/32/64k depending on the user rate
	.rate = OSMO_I460_RATE_64k,
	.bit_offset = 0,
	.demux = {
		.num_bits = 80,
		.out_cb_bits = i460_out_bits_cb,
		.out_cb_bytes = NULL,
		.user_data = NULL,
	},
};

int main(int argc, char **argv)
{

	osmo_i460_ts_init(&g_i460_ts);
	osmo_i460_subchan_add(NULL, &g_i460_ts, &g_i460_chd);
	g_sync_fi = osmo_trau_sync_alloc(NULL, "V110", frame_bits_cb, OSMO_TRAU_SYNCP_V110, NULL);

	struct osmo_soft_uart_cfg suart_cfg = {
		.num_data_bits = 8,
		.num_stop_bits = 1,
		.parity_mode = OSMO_SUART_PARITY_NONE,
		.rx_buf_size = 1024,
		.rx_timeout_ms = 100,
		.priv = NULL,
		.rx_cb = uart_rx_cb,
		.status_change_cb = NULL,
	};
	g_suart = osmo_soft_uart_alloc(NULL, "V110_uart");
	OSMO_ASSERT(g_suart);
	OSMO_ASSERT(osmo_soft_uart_configure(g_suart, &suart_cfg) == 0);
	OSMO_ASSERT(osmo_soft_uart_enable(g_suart, 1, 0) == 0);

	open_and_process(argv[1], NULL);

	/* disable Rx to flush any pending characters */
	osmo_soft_uart_enable(g_suart, 0 ,0);
}
