/*! \file ipaccess.h */

#pragma once

#include <stdint.h>

#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

struct ipaccess_head {
	uint16_t len;	/* network byte order */
	uint8_t proto;
	uint8_t data[0];
} __attribute__ ((packed));

struct ipaccess_head_ext {
	uint8_t proto;
	uint8_t data[0];
} __attribute__ ((packed));

enum ipaccess_proto {
	IPAC_PROTO_RSL		= 0x00,
	IPAC_PROTO_IPACCESS	= 0xfe,
	IPAC_PROTO_SCCP		= 0xfd,
	IPAC_PROTO_OML		= 0xff,


	/* OpenBSC extensions */
	IPAC_PROTO_OSMO		= 0xee,
	IPAC_PROTO_MGCP_OLD	= 0xfc,
};

enum ipaccess_proto_ext {
	IPAC_PROTO_EXT_CTRL	= 0x00,
	IPAC_PROTO_EXT_MGCP	= 0x01,
	IPAC_PROTO_EXT_LAC	= 0x02,
	IPAC_PROTO_EXT_SMSC	= 0x03,
	IPAC_PROTO_EXT_ORC	= 0x04,		/* OML Router Control */
	IPAC_PROTO_EXT_GSUP	= 0x05,		/* GSUP GPRS extension */
	IPAC_PROTO_EXT_OAP	= 0x06,		/* Osmocom Authn Protocol */
	IPAC_PROTO_EXT_RSPRO	= 0x07,		/* Remote SIM protocol */
	IPAC_PROTO_EXT_PCU	= 0x08,		/* BSC<->BTS<->PCU communication */
};

enum ipaccess_msgtype {
	IPAC_MSGT_PING		= 0x00,		/* Heartbeet */
	IPAC_MSGT_PONG		= 0x01,		/* Heartbeat Ack */
	IPAC_MSGT_ID_GET	= 0x04,		/* Identity Request */
	IPAC_MSGT_ID_RESP	= 0x05,		/* Identity */
	IPAC_MSGT_ID_ACK	= 0x06,		/* Identity Ack */
	IPAC_MSGT_ID_NACK	= 0x07,		/* Identity Nack */
	IPAC_MSGT_PROXY		= 0x08,		/* Proxy */
	IPAC_MSGT_PROXY_ACK	= 0x09,		/* Proxy Ack */
	IPAC_MSGT_PROXY_NACK	= 0x0a,		/* Proxy Nack */
	IPAC_MSGT_SSL_INFO	= 0x0b,		/* SSL Info */

	/* OpenBSC extension */
	IPAC_MSGT_SCCP_OLD	= 0xff,
};

enum ipaccess_id_tags {
	IPAC_IDTAG_SERNR		= 0x00,	/* Unit Serial Number */
	IPAC_IDTAG_UNITNAME		= 0x01,	/* Unit Name */
	IPAC_IDTAG_LOCATION1		= 0x02,	/* Unit Location */
	IPAC_IDTAG_LOCATION2		= 0x03,	/* Unit Type */
	IPAC_IDTAG_EQUIPVERS		= 0x04,	/* Hardware Version */
	IPAC_IDTAG_SWVERSION		= 0x05,	/* Software Version */
	IPAC_IDTAG_IPADDR		= 0x06,	/* IP Address */
	IPAC_IDTAG_MACADDR		= 0x07,	/* Ethernet Address */
	IPAC_IDTAG_UNIT			= 0x08,	/* Unit ID */
	IPAC_IDTAG_USERNAME		= 0x09,	/* User Name */
	IPAC_IDTAG_PASSWORD		= 0x0a,	/* Password */
	IPAC_IDTAG_ACCESS_CLASS		= 0x0b, /* Access Class */
	IPAC_IDTG_APP_PROTO_VER		= 0x0c, /* Application Protocol Version */
};

/*
 * Firmware specific header
 */
struct sdp_firmware {
	char magic[4];
	char more_magic[2];
	uint16_t more_more_magic;
	uint32_t header_length;
	uint32_t file_length;
	char sw_part[20];
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char version[20];
	uint16_t table_offset;
	/* stuff i don't know */
} __attribute__((packed));

struct sdp_header_entry {
	uint16_t something1;
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char version[20];
	uint32_t length;
	uint32_t addr1;
	uint32_t addr2;
	uint32_t start;
} __attribute__((packed));
