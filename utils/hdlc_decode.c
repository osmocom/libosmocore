#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>

static struct osmo_isdnhdlc_vars g_hdlc;

/* process input buffer of given length; find + process any HDLC frames contained inside,
 * and return the number of bytes consumed from start of inbuf */
static int process_buf(const uint8_t *inbuf, size_t inlen)
{
	uint8_t outbuf[4096];
	int rc, count;
	size_t in_offset = 0;

#if 0
	while ((rc = osmo_isdnhdlc_decode(&g_hdlc, inbuf + in_offset, inlen - in_offset, &count,
					  outbuf, sizeof(outbuf))) != 2) {
#else
	while (true) {
		rc = osmo_isdnhdlc_decode(&g_hdlc, inbuf + in_offset, inlen - in_offset, &count,
					  outbuf, sizeof(outbuf));
#endif
		//printf("rc=%d, inlen=%zu, in_offset=%zu, count=%d\n", rc, inlen, in_offset, count);
		if (rc > 0) {
			int frlen = rc;
			printf("%s\n", osmo_hexdump(outbuf, frlen));
		} else {
			switch (rc) {
			case -OSMO_HDLC_FRAMING_ERROR:
				fprintf(stderr, "FRAMING_ERR\n");
				break;
			case -OSMO_HDLC_CRC_ERROR:
				fprintf(stderr, "CRC_ERR\n");
				break;
			case -OSMO_HDLC_LENGTH_ERROR:
				fprintf(stderr, "LEN_ERR\n");
				break;
			}
		}
		in_offset += count;
		if (in_offset >= inlen)
			break;
	}

	return in_offset;
}

static int open_and_process(const char *fname)
{
	int fd = open(fname, O_RDONLY);
	if (fd < 0)
		return fd;

	int read_offset = 0;

	while (true) {
		uint8_t inbuf[4096];
		int rc, inlen, count;

		/* read a chunk of data */
		rc = read(fd, inbuf + read_offset, sizeof(inbuf) - read_offset);
		if (rc <= 0)
			return rc;
		/* available length */
		inlen = read_offset + rc;
		//printf("read %d bytes to read_offset=%u => %d available bytes\n", rc, read_offset, inlen);

		count = process_buf(inbuf, inlen);
		//printf("processed %d bytes from inbuf\n", count);
		if (count == inlen) {
			read_offset = 0;
		} else  if (count < inlen) {
			//printf("moving %d remaining bytes to start of inbuf\n", inlen-count);
			memmove(inbuf, inbuf + count, inlen - count);
			read_offset = inlen - count;
		}
	}
}

int main(int argc, char **argv)
{
	osmo_isdnhdlc_rcv_init(&g_hdlc, OSMO_HDLC_F_BITREVERSE);

	return open_and_process(argv[1]);
}
