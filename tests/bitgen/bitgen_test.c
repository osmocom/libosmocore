#include <inttypes.h>
#include <osmocom/core/bit16gen.h>
#include <osmocom/core/bit32gen.h>
#include <osmocom/core/bit64gen.h>

#define DO_TEST(BE_LE, SIZE) do { \
		int8_t len; \
		printf("--- " #SIZE " " #BE_LE "\n"); \
		for (len = SIZE / 8; len > 0; len--) { \
			uint8_t buf[len * 2]; \
			uint8_t at_idx; \
			uint##SIZE##_t val = (uint##SIZE##_t)0x8877665544332211; \
			\
			for (at_idx = 0; at_idx < len; at_idx++) { \
				uint##SIZE##_t read_val = 0; \
				memset(buf, 0, sizeof(buf)); \
				osmo_store##SIZE##BE_LE##_ext(val, &buf[at_idx], len); \
				printf("osmo_store" #SIZE #BE_LE "_ext(0x%" PRIx##SIZE ", &buf[%d], %d) = %s\n", \
				       val, \
				       at_idx, len, osmo_hexdump(buf, sizeof(buf))); \
				\
				read_val = osmo_load##SIZE##BE_LE##_ext(&buf[at_idx], len); \
				printf("osmo_load" #SIZE #BE_LE "_ext(&buf[%d], %d) = 0x%" PRIx##SIZE "\n", \
				       at_idx, len, read_val); \
				\
				if (!strcmp(#BE_LE, "be")) { \
					read_val = osmo_load##SIZE##BE_LE##_ext_2(&buf[at_idx], len); \
					printf("osmo_load" #SIZE #BE_LE "_ext_2(&buf[%d], %d) = 0x%" PRIx##SIZE "\n", \
					       at_idx, len, read_val); \
				} \
			} \
		} \
	} while (0)

/* Shims to allow compiling, the *le_ext_2 are not actually invoked because of the strcmp() condition above. */
#define osmo_load16le_ext_2 dummy
#define osmo_load32le_ext_2 dummy
#define osmo_load64le_ext_2 dummy

static inline uint64_t dummy(const void *p, uint8_t n)
{
	OSMO_ASSERT(false);
}

int main(int argc, char **argv)
{
	DO_TEST(be, 16);
	DO_TEST(le, 16);
	DO_TEST(be, 32);
	DO_TEST(le, 32);
	DO_TEST(be, 64);
	DO_TEST(le, 64);

	{
		printf("--- store/load 0x112233 as 24bit big-endian, legacy\n");
		uint8_t buf[4];
		memset(buf, 0, sizeof(buf));
		osmo_store32be_ext(0x00112233, buf, 3); // stores 11 22 33
		printf("%s\n", osmo_hexdump(buf, 4));
		uint32_t r = osmo_load32be_ext(buf, 3); // returns 0x11223300, not 0x00112233
		printf("0x%x\n", r);
	}

	{
		printf("--- store/load 0x112233 as 24bit big-endian\n");
		uint8_t buf[4];
		memset(buf, 0, sizeof(buf));
		osmo_store32be_ext(0x00112233, buf, 3); // stores 11 22 33
		printf("%s\n", osmo_hexdump(buf, 4));
		uint32_t r = osmo_load32be_ext_2(buf, 3); // returns 0x00112233
		printf("0x%x\n", r);
	}

	{
		printf("--- store/load 0x112233 as 24bit little-endian\n");
		uint8_t buf[4];
		memset(buf, 0, sizeof(buf));
		osmo_store32le_ext(0x00112233, buf, 3); // stores 33 22 11
		printf("%s\n", osmo_hexdump(buf, 4));
		uint32_t r = osmo_load32le_ext(buf, 3); // returns 0x00112233
		printf("0x%x\n", r);
	}

	return 0;
}
