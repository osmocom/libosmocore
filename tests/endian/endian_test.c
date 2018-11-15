#include <osmocom/core/byteswap.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/endian.h>

int main(int argc, char **argv)
{
	printf("Testing 16bit swappinng\n");
	OSMO_ASSERT(osmo_swab16(0x1234) == 0x3412);
	printf("Testing 32bit swappinng\n");
	OSMO_ASSERT(osmo_swab32(0x12345678) == 0x78563412);

	printf("Testing ntohX() and htonX()\n");
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#if OSMO_IS_LITTLE_ENDIAN == 0
#error "Something wrong with endianness detection!"
#endif /* IS_LITTLE_ENDIAN */
	OSMO_ASSERT(osmo_ntohs(0x1234) == 0x3412);
	OSMO_ASSERT(osmo_htons(0x1234) == 0x3412);
	OSMO_ASSERT(osmo_htonl(0x12345678) == 0x78563412);
	OSMO_ASSERT(osmo_ntohl(0x12345678) == 0x78563412);
#else
#if OSMO_IS_LITTLE_ENDIAN == 1
#error "Something wrong with endianness detection!"
#endif /* IS_LITTLE_ENDIAN */
	OSMO_ASSERT(osmo_ntohs(0x1234) == 0x1234);
	OSMO_ASSERT(osmo_htons(0x1234) == 0x1234);
	OSMO_ASSERT(osmo_htonl(0x12345678) == 0x12345678);
	OSMO_ASSERT(osmo_ntohl(0x12345678) == 0x12345678);
#endif /* __BYTE_ORDER__ */

	exit(0);
}
