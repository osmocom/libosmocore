/* -----------------------------------------------------------------------
 * code extracted from 3GPP TS 35.231, annex E for Keccak core functions
 * https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=2402
 *-----------------------------------------------------------------------*/

/* this is the trick to make the code cross-platform
 * at least, Win32 / Linux */

#if defined(_WIN32) || defined(__WIN32__)
#	include <windows.h>
#	define EXPORTIT __declspec(dllexport)
#else
#	define EXPORTIT
#endif

#include <stdint.h>

/*------------------------------------------------------------------------
 * KeccakP-1600-3gpp.h
 *------------------------------------------------------------------------*/

EXPORTIT void Keccak_f_8 (uint8_t s[200]);
EXPORTIT void Keccak_f_32(uint32_t s[50]);
EXPORTIT void Keccak_f_64(uint64_t s[25]);

