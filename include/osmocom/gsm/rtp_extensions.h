/*
 * Themyscira Wireless Technical Specification TW-TS-003 defines a BSSMAP
 * extension whereby a CN implementation and a BSS implementation can
 * negotiate the use of non-3GPP-standard extensions to RTP user plane,
 * extensions that modify RTP formats counter to the stipulations of
 * 3GPP TS 48.103.  There is also a private Osmocom-defined IE in Abis RSL
 * that communicates the same RTP extensions from OsmoBSC to OsmoBTS.
 *
 * This header file defines the meaning of the bits in the first (and currently
 * only) value octet of the TLV IE added to BSSMAP and RSL interfaces,
 * namely, GSM0808_IE_THEMWI_RTP_EXTENSIONS and RSL_IE_OSMO_RTP_EXTENSIONS.
 * It is based on this authoritative definition:
 *
 * https://www.freecalypso.org/specs/tw-ts-003-v010100.txt
 *
 * Section 5.3 in the above specification defines the assignment of
 * individual bits in the single value octet.
 */

#pragma once

#define	OSMO_RTP_EXT_TWTS001	0x01
#define	OSMO_RTP_EXT_TWTS002	0x02
#define	OSMO_RTP_EXT_TWTS006	0x04
#define	OSMO_RTP_EXT_TWTS007	0x08
