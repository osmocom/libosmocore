#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/soft_uart.h>
#include <osmocom/gsm/gsm44021.h>
#include <osmocom/isdn/v110.h>

static struct osmo_soft_uart *g_suart;

static void uart_rx_cb(void *priv, struct msgb *rx_data, unsigned int flags)
{
	char *data = (char *)msgb_data(rx_data);

	fprintf(stdout, "%s(): %s\n", __func__, msgb_hexdump(rx_data));
	for (unsigned int i = 0; i < msgb_length(rx_data); i++) {
		fputc(data[i], stdout);
		if (data[i] == '\r')
			fputc('\n', stdout);
	}

	fputc('\n', stdout);
	msgb_free(rx_data);
}

static const struct osmo_soft_uart_cfg suart_cfg = {
	.num_data_bits = 8,
	.num_stop_bits = 1,
	.parity_mode = OSMO_SUART_PARITY_NONE,
	.rx_buf_size = 1024,
	.rx_timeout_ms = 100,
	.priv = NULL,
	.rx_cb = uart_rx_cb,
	.status_change_cb = NULL,
};

static void swap_words(uint8_t *data, size_t data_len)
{
	/* swap bytes in words */
	while (data_len >= 2) {
		uint8_t tmp = data[0];
		data[0] = data[1];
		data[1] = tmp;

		data_len -= 2;
		data += 2;
	}
}

static void decode_record(uint8_t *record)
{
	ubit_t data[4 * 60];

	/* XXX: assuming TCH/F9.6 (4 * 60 = 240 bits or 30 bytes) */

	/* the layer1 firmware emits frames with swapped words (LE ordering) */
	swap_words(record, 30);
	/* unpack packed bits (MSB goes first) */
	osmo_pbit2ubit_ext(data, 0, record, 0, sizeof(data), 1);

	for (unsigned int i = 0; i < 4; i++) {
		struct osmo_v110_decoded_frame df = { 0 };

		osmo_csd_12k_6k_decode_frame(&df, &data[i * 60], 60);

#if 1
		fprintf(stderr, "S: %s\n", osmo_ubit_dump(df.s_bits, sizeof(df.s_bits)));
		fprintf(stderr, "X: %s\n", osmo_ubit_dump(df.x_bits, sizeof(df.x_bits)));
		fprintf(stderr, "E: %s\n", osmo_ubit_dump(df.e_bits, sizeof(df.e_bits)));
		fprintf(stderr, "D: %s\n", osmo_ubit_dump(df.d_bits, sizeof(df.d_bits)));
#endif

		/* XXX: what do we do with S-/X-/E-bits? */
		osmo_soft_uart_rx_ubits(g_suart, &df.d_bits[0], sizeof(df.d_bits));
	}
}

/* osmocom-bb/layer1 firmware emits TRAFFIC.ind with len=33 */
#define RECORD_LEN 33

static int open_and_process(const char *fname)
{
	uint8_t buf[RECORD_LEN];
	int fd;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return fd;

	while (true) {
		int rc = read(fd, buf, sizeof(buf));
		if (rc <= 0)
			return rc;
		decode_record(&buf[0]);
	}

	close(fd);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s FILE\n", argv[0]);
		return 1;
	}

	g_suart = osmo_soft_uart_alloc(NULL, "V110_csd_uart");
	OSMO_ASSERT(g_suart);

	OSMO_ASSERT(osmo_soft_uart_configure(g_suart, &suart_cfg) == 0);
	OSMO_ASSERT(osmo_soft_uart_enable(g_suart, 1, 0) == 0);

	open_and_process(argv[1]);

	/* disable Rx to flush any pending characters */
	osmo_soft_uart_enable(g_suart, 0, 0);

	return 0;
}
