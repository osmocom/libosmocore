/*! \file sim.h
 * Routines for helping with SIM (ISO/IEC 7816-4 more generally) communication.
 */

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>

#define APDU_HDR_LEN	5
#define MAX_AID_LEN	16 /* Table 13.2 of TS 102 221 */


/*! Maximum Answer-To-Reset (ATR) size in bytes
 *  @note defined in ISO/IEC 7816-3:2006(E) section 8.2.1 as 32, on top the initial character TS of section 8.1
 *  @remark technical there is no size limitation since Yi present in T0,TDi will indicate if more interface bytes are present, including TDi+i
 */
#define OSIM_MAX_ATR_LEN 33

/*! command-response pairs cases
 *
 * Enumeration used to identify the APDU structure based on command-response pair case , as specified in ISO/IEC 7816-3:2006(E) §12.1.
 */
enum osim_apdu_case {
	APDU_CASE_1, /*!< command header, no command data field, no response data field */
	APDU_CASE_2S, /*!< command header, no command data field, response data field (short) */
	APDU_CASE_2E, /*!< command header, no command data field, response data field (extended) */
	APDU_CASE_3S, /*!< command header, command data field (short), no response data field */
	APDU_CASE_3E, /*!< command header, command data field (extended), no response data field */
	APDU_CASE_4S, /*!< command header, command data field (short), response data field (short) */
	APDU_CASE_4E /*!< command header, command data field (extended), response data field (extended) */
};

/*! APDU/TPDU command header
 *
 * This structure encode an APDU/TPDU command header, as specified in ISO/IEC 7816-3:2006(E) §12.2 and §12.3.
 * The APDU (application layer) can be encoded as different TPDUs (transport layer), depending on the transport protocol used.
 * The TPDU encoding by T=1 of the APDU command header is identical to the APDU.
 * The TPDU encoding by T=0 of the APDU command header adds a Parameter 3 field, generally used instead of Lc/Le.
 * 
 * @todo have different structures for APDU, TPDU by T=0, and TPDU by T=1.
 */
struct osim_apdu_cmd_hdr {
	uint8_t cla; /*!< CLASS byte */
	uint8_t ins; /*!< INSTRUCTION byte */
	uint8_t p1; /*!< Parameter 1 byte */
	uint8_t p2; /*!< Parameter 2 byte */
	uint8_t p3; /*!< Parameter 3 byte, used for TPDU by T=0 */
} __attribute__ ((packed));

#define msgb_apdu_dr(__x)

/*! APDU command body
 *
 * This structure encode a command body, as specified in ISO/IEC 7816-3:2006(E) §12.1.
 * The data and response contents should be provided along with this structure.
 */
struct osim_msgb_cb {
	enum osim_apdu_case apduc; /*!< command-response pair case, defining the encoding of Lc and Le */
	uint16_t lc; /*!< number of bytes in the command data field Nc, which will encoded in 0, 1 or 3 bytes into Lc, depending on the case */
	uint16_t le; /*!< maximum number of bytes expected in the response data field,  which will encoded in 0, 1, 2 or 3 bytes into Le, depending on the case */
	uint16_t sw; /*!< status word, composed of SW1 and SW2 bytes */
} __attribute__((__may_alias__));
#define OSIM_MSGB_CB(__msgb)	((struct osim_msgb_cb *)&((__msgb)->cb[0]))
/*! status word from msgb->cb */
#define msgb_apdu_case(__x)	OSIM_MSGB_CB(__x)->apduc
#define msgb_apdu_lc(__x)	OSIM_MSGB_CB(__x)->lc
#define msgb_apdu_le(__x)	OSIM_MSGB_CB(__x)->le
#define msgb_apdu_sw(__x)	OSIM_MSGB_CB(__x)->sw
/*! pointer to the command header of the APDU */
#define msgb_apdu_h(__x)	((struct osim_apdu_cmd_hdr *)(__x)->l2h)

#define msgb_apdu_dc(__x)	((__x)->l2h + sizeof(struct osim_apdu_cmd_hdr))
#define msgb_apdu_de(__x)	((__x)->l2h + sizeof(struct osim_apdu_cmd_hdr) + msgb_apdu_lc(__x))

int osim_init(void *ctx);

/* FILES */

struct osim_file;
struct osim_file_desc;
struct osim_decoded_data;

/*! Operations for a given File */
struct osim_file_ops {
	/*! Parse binary file data into osim_decoded_data */
	int (*parse)(struct osim_decoded_data *dd,
		     const struct osim_file_desc *desc,
		     int len, uint8_t *data);
	/*! Encode osim_decoded_data into binary file */
	struct msgb * (*encode)(const struct osim_file_desc *desc,
				const struct osim_decoded_data *decoded);
};

enum osim_element_type {
	ELEM_T_NONE,
	ELEM_T_BOOL,	/*!< a boolean flag */
	ELEM_T_UINT8,	/*!< unsigned integer */
	ELEM_T_UINT16,	/*!< unsigned integer */
	ELEM_T_UINT32,	/*!< unsigned integer */
	ELEM_T_STRING,	/*!< generic string */
	ELEM_T_BCD,	/*!< BCD encoded digits */
	ELEM_T_BYTES,	/*!< BCD encoded digits */
	ELEM_T_GROUP,	/*!< group container, has siblings */
};

enum osim_element_repr {
	ELEM_REPR_NONE,
	ELEM_REPR_DEC,
	ELEM_REPR_HEX,
};

/*! A single decoded element inside a file */
struct osim_decoded_element {
	struct llist_head list;

	enum osim_element_type type;
	enum osim_element_repr representation;
	const char *name;

	unsigned int length;
	union {
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
		uint8_t *buf;
		/*! A list of sibling decoded_items */
		struct llist_head siblings;
	} u;
};

/*! Decoded data for a single file, consisting of all decoded elements */
struct osim_decoded_data {
	/*! file to which we belong */
	const struct osim_file *file;
	/*! list of 'struct decoded_element' */
	struct llist_head decoded_elements;
};


enum osim_file_type {
	TYPE_NONE,
	TYPE_DF,	/*!< Dedicated File */
	TYPE_ADF,	/*!< Application Dedicated File */
	TYPE_EF,	/*!< Entry File */
	TYPE_EF_INT,	/*!< Internal Entry File */
	TYPE_MF,	/*!< Master File */
};

enum osim_ef_type {
	EF_TYPE_TRANSP,		/*!< Transparent EF */
	EF_TYPE_RECORD_FIXED,	/*!< Fixed-Size Record EF */
	EF_TYPE_RECORD_CYCLIC,	/*!< Cyclic Record EF */
	EF_TYPE_KEY,		/*!< Key file as used in TETRA */
};

#define F_OPTIONAL		0x0001

#define SFI_NONE 		0xFF

struct osim_file_desc {
	struct llist_head list;		/*!< local element in list */
	struct llist_head child_list;	/*!< list of children EF in DF */
	struct osim_file_desc *parent;	/*!< parent DF */

	enum osim_file_type type;	/*!< Type of the file (EF, DF, ...) */
	enum osim_ef_type ef_type;	/*!< Type of the EF, if type == TYPE_EF */

	uint16_t fid;			/*!< File Identifier */
	uint8_t sfid;			/*!< Short File IDentifier */
	const uint8_t *df_name;
	uint8_t df_name_len;

	const char *short_name;		/*!< Short Name (like EF.ICCID) */
	const char *long_name;		/*!< Long / description */
	unsigned int flags;

	struct osim_file_ops ops;	/*!< Operations (parse/encode */

	struct {
		size_t min;		/*!< Minimum size of the file
					  (transparent) or record in
					  cyclic / linear file */
		size_t rec;		/*!< Recommended size */
	} size;
};

/*! A single instance of a file: Descriptor and contents */
struct osim_file {
	/*! Descriptor for the file */
	const struct osim_file_desc *desc;

	/*! Encoded file contents */
	struct msgb *encoded_data;
	/*! Parsed/Decoded file contents */
	struct osim_decoded_data *decoded_data;
};

/*! Convenience macros for defining EF */
#define EF(pfid, sfi, pns, pflags, pnl, ptype, smin, srec, pdec, penc)	\
	{								\
		.fid		= pfid,					\
		.sfid		= sfi,					\
		.type		= TYPE_EF,				\
		.ef_type	= ptype,				\
		.short_name	= pns,					\
		.long_name	= pnl,					\
		.flags		= pflags,				\
		.ops 		= { .encode = penc, .parse = pdec },	\
		.size		= { .min = smin, .rec = srec},		\
	}


/*! Convenience macros for defining EF */
#define EF_TRANSP(fid, sfi, ns, flags, smin, srec, nl, dec, enc)	\
		EF(fid, sfi, ns, flags, nl, EF_TYPE_TRANSP,		\
		   smin, srec, dec, enc)
/*! Convenience macros for defining EF */
#define EF_TRANSP_N(fid, sfi, ns, flags, smin, srec, nl)		\
		EF_TRANSP(fid, sfi, ns, flags, smin, srec,		\
			  nl, &default_decode, NULL)

/*! Convenience macros for defining EF */
#define EF_CYCLIC(fid, sfi, ns, flags, smin, srec, nl, dec, enc)	\
		EF(fid, sfi, ns, flags, nl, EF_TYPE_RECORD_CYCLIC,	\
		   smin, srec, dec, enc)
/*! Convenience macros for defining EF */
#define EF_CYCLIC_N(fid, sfi, ns, flags, smin, srec, nl)		\
		EF_CYCLIC(fid, sfi, ns, flags, smin, srec, nl,		\
			  &default_decode, NULL)

/*! Convenience macros for defining EF */
#define EF_LIN_FIX(fid, sfi, ns, flags, smin, srec, nl, dec, enc)	\
		EF(fid, sfi, ns, flags, nl, EF_TYPE_RECORD_FIXED,	\
		   smin, srec, dec, enc)
/*! Convenience macros for defining EF */
#define EF_LIN_FIX_N(fid, sfi, ns, flags, smin, srec, nl)		\
		EF_LIN_FIX(fid, sfi, ns, flags, smin, srec, nl, 	\
			   &default_decode, NULL)

/*! Convenience macros for defining EF */
#define EF_KEY(fid, sfi, ns, flags, smin, srec, nl, dec, enc)		\
		EF(fid, sfi, ns, flags, nl, EF_TYPE_KEY,		\
		   smin, srec, dec, enc)
/*! Convenience macros for defining EF */
#define EF_KEY_N(fid, sfi, ns, flags, smin, srec, nl)			\
		EF_KEY(fid, sfi, ns, flags, smin, srec, nl, 		\
		       &default_decode, NULL)


struct osim_file_desc *
osim_file_desc_find_name(struct osim_file_desc *parent, const char *name);

struct osim_file_desc *
osim_file_desc_find_aid(struct osim_file_desc *parent, const uint8_t *aid, uint8_t aid_len);

struct osim_file_desc *
osim_file_desc_find_fid(struct osim_file_desc *parent, uint16_t fid);

struct osim_file_desc *
osim_file_desc_find_sfid(struct osim_file_desc *parent, uint8_t sfid);

/* STATUS WORDS */

enum osim_card_sw_type {
	SW_TYPE_NONE,
	SW_TYPE_STR,
};

enum osim_card_sw_class {
	SW_CLS_NONE,
	SW_CLS_OK,
	SW_CLS_POSTP,
	SW_CLS_WARN,
	SW_CLS_ERROR,
};

/*! A card status word (SW) */
struct osim_card_sw {
	/*! status word code (2 bytes) */
	uint16_t code;
	/*! status word mask (2 bytes), to match range/prefix of SW */
	uint16_t mask;
	enum osim_card_sw_type type;
	enum osim_card_sw_class class;
	union {
		/*! Human-readable meaning of SW */
		const char *str;
	} u;
};

#define OSIM_CARD_SW_LAST	{			\
	.code = 0, .mask = 0, .type = SW_TYPE_NONE,	\
	.class = SW_CLS_NONE, .u.str = NULL		\
}

/*! A card application (e.g. USIM, ISIM, HPSIM) */
struct osim_card_app_profile {
	/*! entry in the global list of card application profiles */
	struct llist_head list;
	/*! human-readable name */
	const char *name;
	/*! AID of this application, as used in EF.DIR */
	uint8_t aid[MAX_AID_LEN];
	uint8_t aid_len;
	/*! file system description */
	struct osim_file_desc *adf;
	/*! Status words defined by application */
	const struct osim_card_sw *sw;
};

const struct osim_card_app_profile *
osim_app_profile_find_by_name(const char *name);

const struct osim_card_app_profile *
osim_app_profile_find_by_aid(const uint8_t *aid, uint8_t aid_len);

const struct osim_card_sw *osim_app_profile_find_sw(const struct osim_card_app_profile *ap, uint16_t sw_in);

/*! A card profile (e.g. SIM card */
struct osim_card_profile {
	const char *name;
	/*! Descriptor for the MF (root directory */
	struct osim_file_desc *mf;
	/*! Array of pointers to status words */
	const struct osim_card_sw **sws;
};

const struct osim_card_sw *osim_cprof_find_sw(const struct osim_card_profile *cp, uint16_t sw_in);

struct osim_chan_hdl;
enum osim_card_sw_class osim_sw_class(const struct osim_chan_hdl *ch, uint16_t sw_in);
char *osim_print_sw_buf(char *buf, size_t buf_len, const struct osim_chan_hdl *ch, uint16_t sw_in);
char *osim_print_sw(const struct osim_chan_hdl *ch, uint16_t sw_in);
char *osim_print_sw_c(const void *ctx, const struct osim_chan_hdl *ch, uint16_t sw_in);

extern const struct tlv_definition ts102221_fcp_tlv_def;
extern const struct value_string ts102221_fcp_vals[14];

/* 11.1.1.3 */
enum ts102221_fcp_tag {
	UICC_FCP_T_FCP		= 0x62,
	UICC_FCP_T_FILE_SIZE	= 0x80,
	UICC_FCP_T_TOT_F_SIZE	= 0x81,
	UICC_FCP_T_FILE_DESC	= 0x82,
	UICC_FCP_T_FILE_ID	= 0x83,
	UICC_FCP_T_DF_NAME	= 0x84,
	UICC_FCP_T_SFID		= 0x88,
	UICC_FCP_T_LIFEC_STS	= 0x8A,
	UICC_FCP_T_SEC_ATTR_REFEXP= 0x8B,
	UICC_FCP_T_SEC_ATTR_COMP= 0x8C,
	UICC_FCP_T_PROPRIETARY	= 0xA5,
	UICC_FCP_T_SEC_ATTR_EXP	= 0xAB,
	UICC_FCP_T_PIN_STS_DO	= 0xC6,
};

struct msgb *osim_new_apdumsg(uint8_t cla, uint8_t ins, uint8_t p1,
			      uint8_t p2, uint16_t lc, uint16_t le);

/* CARD READERS */

enum osim_proto {
	OSIM_PROTO_T0	= 0,
	OSIM_PROTO_T1	= 1,
};

enum osim_reader_driver {
	OSIM_READER_DRV_PCSC = 0,
	OSIM_READER_DRV_OPENCT = 1,
	OSIM_READER_DRV_SERIAL = 2,
};

struct osim_reader_ops {
	const char *name;
	struct osim_reader_hdl *(*reader_open)(int idx, const char *name, void *ctx);
	struct osim_card_hdl *(*card_open)(struct osim_reader_hdl *rh, enum osim_proto proto);
	int (*card_reset)(struct osim_card_hdl *card, bool cold_reset);
	int (*card_close)(struct osim_card_hdl *card);
	int (*transceive)(struct osim_reader_hdl *rh, struct msgb *msg);
};

struct osim_reader_hdl {
	/*! member in global list of readers */
	struct llist_head list;
	const struct osim_reader_ops *ops;
	uint32_t proto_supported;
	void *priv;
	/*! current card, if any */
	struct osim_card_hdl *card;
};

/*! descriptor for a given application present on a card */
struct osim_card_app_hdl {
	/*! member in card list of applications */
	struct llist_head list;
	/*! AID of the application */
	uint8_t aid[MAX_AID_LEN];
	uint8_t aid_len;
	/*! application label from EF_DIR */
	char *label;
	/*! application profile (if any known) */
	const struct osim_card_app_profile *prof;
};

struct osim_card_hdl {
	/*! member in global list of cards */
	struct llist_head list;
	/*! reader through which card is accessed */
	struct osim_reader_hdl *reader;
	/*! card profile */
	struct osim_card_profile *prof;
	/*! card protocol */
	enum osim_proto proto;

	/*! list of channels for this card */
	struct llist_head channels;

	/*! list of applications found on card */
	struct llist_head apps;

	/*! ATR (Answer To Reset) of the card */
	uint8_t atr[OSIM_MAX_ATR_LEN];
	unsigned int atr_len;
};

struct osim_chan_hdl {
	/*! linked to card->channels */
	struct llist_head list;
	/*! card to which this channel belongs */
	struct osim_card_hdl *card;
	/*! current working directory */
	const struct osim_file_desc *cwd;
	/*! currently selected application (if any) */
	struct osim_card_app_hdl *cur_app;
};

int osim_card_hdl_add_app(struct osim_card_hdl *ch, const uint8_t *aid, uint8_t aid_len,
			  const char *label);

/* reader.c */
int osim_transceive_apdu(struct osim_chan_hdl *st, struct msgb *amsg);
struct osim_reader_hdl *osim_reader_open(enum osim_reader_driver drv, int idx,
					 const char *name, void *ctx);
struct osim_card_hdl *osim_card_open(struct osim_reader_hdl *rh, enum osim_proto proto);
int osim_card_reset(struct osim_card_hdl *card, bool cold_reset);
int osim_card_close(struct osim_card_hdl *card);
