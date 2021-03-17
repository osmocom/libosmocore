#pragma once

#include <stdint.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/bit16gen.h>
#include <osmocom/core/bit32gen.h>

/*! \defgroup tlv TLV parser
 *  @{
 * \file tlv.h */

/* Terminology / wording
		tag	length		value	(in bits)

	    V	-	-		8
	   LV	-	8		N * 8
	  TLV	8	8		N * 8
	TL16V	8	16		N * 8
	TLV16	8	8		N * 16
	 TvLV	8	8/16		N * 8
	vTvLV	8/16	8/16		N * 8
	T16LV	16	8		N * 8
*/

/*! gross length of a LV type field */
#define LV_GROSS_LEN(x)		(x+1)
/*! gross length of a TLV type field */
#define TLV_GROSS_LEN(x)	(x+2)
/*! gross length of a TLV16 type field */
#define TLV16_GROSS_LEN(x)	((2*x)+2)
/*! gross length of a TL16V type field */
#define TL16V_GROSS_LEN(x)	(x+3)
/*! gross length of a L16TV type field */
#define L16TV_GROSS_LEN(x)	(x+3)
/*! gross length of a T16LV type field */
#define T16LV_GROSS_LEN(x)	(x+3)

/*! maximum length of TLV of one byte length */
#define TVLV_MAX_ONEBYTE	0x7f

/*! error return codes of various TLV parser functions */
enum osmo_tlv_parser_error {
	OSMO_TLVP_ERR_OFS_BEYOND_BUFFER		= -1,
	OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER	= -2,
	OSMO_TLVP_ERR_UNKNOWN_TLV_TYPE		= -3,

	OSMO_TLVP_ERR_MAND_IE_MISSING		= -50,
	OSMO_TLVP_ERR_IE_TOO_SHORT		= -51,
};

/*! gross length of a TVLV type field */
static inline uint16_t TVLV_GROSS_LEN(uint16_t len)
{
	if (len <= TVLV_MAX_ONEBYTE)
		return TLV_GROSS_LEN(len);
	else
		return TL16V_GROSS_LEN(len);
}

/*! gross length of vTvL header (tag+len) */
static inline uint16_t VTVL_GAN_GROSS_LEN(uint16_t tag, uint16_t len)
{
	uint16_t ret = 2;

	if (tag > TVLV_MAX_ONEBYTE)
		ret++;

	if (len > TVLV_MAX_ONEBYTE)
		ret++;

	return ret;
}

/*! gross length of vTvLV (tag+len+val) */
static inline uint16_t VTVLV_GAN_GROSS_LEN(uint16_t tag, uint16_t len)
{
	uint16_t ret;

	if (len <= TVLV_MAX_ONEBYTE)
		ret = TLV_GROSS_LEN(len);
	else
		ret = TL16V_GROSS_LEN(len);

	if (tag > TVLV_MAX_ONEBYTE)
		ret += 1;

	return ret;
}

/* TLV generation */

/*! put (append) a LV field */
static inline uint8_t *lv_put(uint8_t *buf, uint8_t len,
				const uint8_t *val)
{
	*buf++ = len;
	memcpy(buf, val, len);
	return buf + len;
}

/*! Append a TLV field, a Tag-Length-Value field.
 * \param[out] buf  Location in a buffer to append TLV at.
 * \param[in] tag  Tag id to write.
 * \param[in] len  Length field to write and amount of bytes to append.
 * \param[in] val  Pointer to data to append, or NULL to append zero data.
 * Always append tag and length. Append \a len bytes read from \a val. If val is NULL, append \a len zero
 * bytes instead. If \a len is zero, do not append any data apart from tag and length. */
static inline uint8_t *tlv_put(uint8_t *buf, uint8_t tag, uint8_t len,
				const uint8_t *val)
{
	*buf++ = tag;
	*buf++ = len;
	if (len) {
		if (val)
			memcpy(buf, val, len);
		else
			memset(buf, 0, len);
	}
	return buf + len;
}

/*! put (append) a TL field (a TLV field but omitting the value part). */
static inline uint8_t *tl_put(uint8_t *buf, uint8_t tag, uint8_t len)
{
	*buf++ = tag;
	*buf++ = len;
	return buf;
}

/*! put (append) a TLV16 field */
static inline uint8_t *tlv16_put(uint8_t *buf, uint8_t tag, uint8_t len,
				const uint16_t *val)
{
	*buf++ = tag;
	*buf++ = len;
	memcpy(buf, val, len*2);
	return buf + len*2;
}

/*! put (append) a TL16V field */
static inline uint8_t *tl16v_put(uint8_t *buf, uint8_t tag, uint16_t len,
				const uint8_t *val)
{
	*buf++ = tag;
	*buf++ = len >> 8;
	*buf++ = len & 0xff;
	memcpy(buf, val, len);
	return buf + len;
}

/*! put (append) a TL16 field. */
static inline uint8_t *tl16_put(uint8_t *buf, uint8_t tag, uint16_t len)
{
	*buf++ = tag;
	*buf++ = len >> 8;
	*buf++ = len & 0xff;
	return buf;
}

/*! put (append) a TL16V field */
static inline uint8_t *t16lv_put(uint8_t *buf, uint16_t tag, uint8_t len,
				const uint8_t *val)
{
	*buf++ = tag >> 8;
	*buf++ = tag & 0xff;
	*buf++ = len;
	memcpy(buf, val, len);
	return buf + len;
}

/*! put (append) a TvLV field */
static inline uint8_t *tvlv_put(uint8_t *buf, uint8_t tag, uint16_t len,
				 const uint8_t *val)
{
	uint8_t *ret;

	if (len <= TVLV_MAX_ONEBYTE) {
		ret = tlv_put(buf, tag, len, val);
		buf[1] |= 0x80;
	} else
		ret = tl16v_put(buf, tag, len, val);

	return ret;
}

/*! put (append) a TvL field (a TvLV with variable-size length, where the value part's length is already known, but will
 * be put() later).
 * \returns pointer to the value's start position.
 */
static inline uint8_t *tvl_put(uint8_t *buf, uint8_t tag, uint16_t len)
{
	uint8_t *ret;

	if (len <= TVLV_MAX_ONEBYTE) {
		ret = tl_put(buf, tag, len);
		buf[1] |= 0x80;
	} else
		ret = tl16_put(buf, tag, len);

	return ret;
}

/*! put (append) a variable-length tag or variable-length length * */
static inline uint8_t *vt_gan_put(uint8_t *buf, uint16_t tag)
{
	if (tag > TVLV_MAX_ONEBYTE) {
		/* two-byte TAG */
		*buf++ = 0x80 | (tag >> 8);
		*buf++ = (tag & 0xff);
	} else
		*buf++ = tag;

	return buf;
}

/* put (append) vTvL (GAN) field (tag + length)*/
static inline uint8_t *vtvl_gan_put(uint8_t *buf, uint16_t tag, uint16_t len)
{
	uint8_t *ret;

	ret = vt_gan_put(buf, tag);
	return vt_gan_put(ret, len);
}

/* put (append) vTvLV (GAN) field (tag + length + val) */
static inline uint8_t *vtvlv_gan_put(uint8_t *buf, uint16_t tag, uint16_t len,
				      const uint8_t *val)
{
	uint8_t *ret;

	ret = vtvl_gan_put(buf, tag, len );

	memcpy(ret, val, len);
	ret = buf + len;

	return ret;
}

/*! put (append) a TLV16 field to \ref msgb */
static inline uint8_t *msgb_tlv16_put(struct msgb *msg, uint8_t tag, uint8_t len, const uint16_t *val)
{
	uint8_t *buf = msgb_put(msg, TLV16_GROSS_LEN(len));
	return tlv16_put(buf, tag, len, val);
}

/*! put (append) a TL16V field to \ref msgb */
static inline uint8_t *msgb_tl16v_put(struct msgb *msg, uint8_t tag, uint16_t len,
					const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, TL16V_GROSS_LEN(len));
	return tl16v_put(buf, tag, len, val);
}

static inline uint8_t *msgb_t16lv_put(struct msgb *msg, uint16_t tag, uint8_t len, const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, T16LV_GROSS_LEN(len));
	return t16lv_put(buf, tag, len, val);
}

/*! put (append) a TvL field to \ref msgb, i.e. a TvLV with variable-size length, where the value's length is already
 * known, but will be put() later. The value section is not yet reserved, only tag and variable-length are put in the
 * msgb.
 * \returns pointer to the value's start position and end of the msgb.
 */
static inline uint8_t *msgb_tvl_put(struct msgb *msg, uint8_t tag, uint16_t len)
{
	uint8_t *buf = msgb_put(msg, TVLV_GROSS_LEN(len));
	return tvl_put(buf, tag, len);
}

/*! put (append) a TvLV field to \ref msgb */
static inline uint8_t *msgb_tvlv_put(struct msgb *msg, uint8_t tag, uint16_t len,
				      const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, TVLV_GROSS_LEN(len));
	return tvlv_put(buf, tag, len, val);
}

/*! put (append) a TvLV field containing a big-endian 16bit value to msgb. */
static inline uint8_t *msgb_tvlv_put_16be(struct msgb *msg, uint8_t tag, uint16_t val)
{
	uint16_t val_be = osmo_htons(val);
	return msgb_tvlv_put(msg, tag, 2, (const uint8_t *)&val_be);
}

/*! put (append) a TvLV field containing a big-endian 16bit value to msgb. */
static inline uint8_t *msgb_tvlv_put_32be(struct msgb *msg, uint8_t tag, uint32_t val)
{
	uint32_t val_be = osmo_htonl(val);
	return msgb_tvlv_put(msg, tag, 4, (const uint8_t *)&val_be);
}

/*! put (append) a vTvLV field to \ref msgb */
static inline uint8_t *msgb_vtvlv_gan_put(struct msgb *msg, uint16_t tag,
					  uint16_t len, const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, VTVLV_GAN_GROSS_LEN(tag, len));
	return vtvlv_gan_put(buf, tag, len, val);
}

/*! put (append) a L16TV field to \ref msgb */
static inline uint8_t *msgb_l16tv_put(struct msgb *msg, uint16_t len, uint8_t tag,
                                       const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, L16TV_GROSS_LEN(len));

	*buf++ = len >> 8;
	*buf++ = len & 0xff;
	*buf++ = tag;
	memcpy(buf, val, len);
	return buf + len;
}

/*! put (append) a V field */
static inline uint8_t *v_put(uint8_t *buf, uint8_t val)
{
	*buf++ = val;
	return buf;
}

/*! put (append) a TV field */
static inline uint8_t *tv_put(uint8_t *buf, uint8_t tag, 
				uint8_t val)
{
	*buf++ = tag;
	*buf++ = val;
	return buf;
}

/*! put (append) a TVfixed field */
static inline uint8_t *tv_fixed_put(uint8_t *buf, uint8_t tag,
				    unsigned int len, const uint8_t *val)
{
	*buf++ = tag;
	memcpy(buf, val, len);
	return buf + len;
}

/*! put (append) a TV16 field
 *  \param[in,out] buf data buffer
 *  \param[in] tag Tag value
 *  \param[in] val Value (in host byte order!)
 */
static inline uint8_t *tv16_put(uint8_t *buf, uint8_t tag, 
				 uint16_t val)
{
	*buf++ = tag;
	*buf++ = val >> 8;
	*buf++ = val & 0xff;
	return buf;
}

/*! put (append) a LV field to a \ref msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_lv_put(struct msgb *msg, uint8_t len, const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, LV_GROSS_LEN(len));
	return lv_put(buf, len, val);
}

/*! put (append) a TLV field to a \ref msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_tlv_put(struct msgb *msg, uint8_t tag, uint8_t len, const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, TLV_GROSS_LEN(len));
	return tlv_put(buf, tag, len, val);
}

/*! put (append) a TV field to a \ref msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_tv_put(struct msgb *msg, uint8_t tag, uint8_t val)
{
	uint8_t *buf = msgb_put(msg, 2);
	return tv_put(buf, tag, val);
}

/*! put (append) a TVfixed field to a \ref msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_tv_fixed_put(struct msgb *msg, uint8_t tag,
					unsigned int len, const uint8_t *val)
{
	uint8_t *buf = msgb_put(msg, 1+len);
	return tv_fixed_put(buf, tag, len, val);
}

/*! put (append) a V field to a \ref msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_v_put(struct msgb *msg, uint8_t val)
{
	uint8_t *buf = msgb_put(msg, 1);
	return v_put(buf, val);
}

/*! put (append) a TL fields to a \ref msgb
 *  \returns pointer to the length field so it can be updated after adding new information under specified tag */
static inline uint8_t *msgb_tl_put(struct msgb *msg, uint8_t tag)
{
	uint8_t *len = msgb_v_put(msg, tag);

	/* reserve space for length, len points to this reserved space already */
	msgb_v_put(msg, 0);

	return len;
}

/*! put (append) a TV16 field (network order) to the given msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_tv16_put(struct msgb *msg, uint8_t tag, uint16_t val)
{
	uint8_t *buf = msgb_put(msg, 3);
	return tv16_put(buf, tag, val);
}

/*! put (append) a TV32 field (network order) to the given msgb
 *  \returns pointer to first byte after newly-put information */
static inline uint8_t *msgb_tv32_put(struct msgb *msg, uint8_t tag, uint32_t val)
{
	uint8_t *buf = msgb_put(msg, 1 + 4);
	*buf++ = tag;
	osmo_store32be(val, buf);
	return msg->tail;
}

/*! push (prepend) a TLV field to a \ref msgb
 *  \returns pointer to first byte of newly-pushed information */
static inline uint8_t *msgb_tlv_push(struct msgb *msg, uint8_t tag, uint8_t len, const uint8_t *val)
{
	uint8_t *buf = msgb_push(msg, TLV_GROSS_LEN(len));
	tlv_put(buf, tag, len, val);
	return buf;
}

/*! push 1-byte tagged value */
static inline uint8_t *msgb_tlv1_push(struct msgb *msg, uint8_t tag, uint8_t val)
{
	return msgb_tlv_push(msg, tag, 1, &val);
}

/*! push (prepend) a TV field to a \ref msgb
 *  \returns pointer to first byte of newly-pushed information */
static inline uint8_t *msgb_tv_push(struct msgb *msg, uint8_t tag, uint8_t val)
{
	uint8_t *buf = msgb_push(msg, 2);
	tv_put(buf, tag, val);
	return buf;
}

/*! push (prepend) a TV16 field to a \ref msgb
 *  \returns pointer to first byte of newly-pushed information */
static inline uint8_t *msgb_tv16_push(struct msgb *msg, uint8_t tag, uint16_t val)
{
	uint8_t *buf = msgb_push(msg, 3);
	tv16_put(buf, tag, val);
	return buf;
}

/*! push (prepend) a TvLV field to a \ref msgb
 *  \returns pointer to first byte of newly-pushed information */
static inline uint8_t *msgb_tvlv_push(struct msgb *msg, uint8_t tag, uint16_t len,
				      const uint8_t *val)
{
	uint8_t *buf = msgb_push(msg, TVLV_GROSS_LEN(len));
	tvlv_put(buf, tag, len, val);
	return buf;
}

/* push (prepend) a vTvL header to a \ref msgb
 */
static inline uint8_t *msgb_vtvl_gan_push(struct msgb *msg, uint16_t tag,
					   uint16_t len)
{
	uint8_t *buf = msgb_push(msg, VTVL_GAN_GROSS_LEN(tag, len));
	vtvl_gan_put(buf, tag, len);
	return buf;
}


static inline uint8_t *msgb_vtvlv_gan_push(struct msgb *msg, uint16_t tag,
					   uint16_t len, const uint8_t *val)
{
	uint8_t *buf = msgb_push(msg, VTVLV_GAN_GROSS_LEN(tag, len));
	vtvlv_gan_put(buf, tag, len, val);
	return buf;
}

/* TLV parsing */

/*! Entry in a TLV parser array */
struct tlv_p_entry {
	uint16_t len;		/*!< length */
	const uint8_t *val;	/*!< pointer to value */
};

/*! TLV type */
enum tlv_type {
	TLV_TYPE_NONE,		/*!< no type */
	TLV_TYPE_FIXED,		/*!< fixed-length value-only */
	TLV_TYPE_T,		/*!< tag-only */
	TLV_TYPE_TV,		/*!< tag-value (8bit) */
	TLV_TYPE_TLV,		/*!< tag-length-value */
	TLV_TYPE_TL16V,		/*!< tag, 16 bit length, value */
	TLV_TYPE_TvLV,		/*!< tag, variable length, value */
	TLV_TYPE_SINGLE_TV,	/*!< tag and value (both 4 bit) in 1 byte */
	TLV_TYPE_vTvLV_GAN,	/*!< variable-length tag, variable-length length */
};

/*! Definition of a single IE (Information Element) */
struct tlv_def {
	enum tlv_type type;	/*!< TLV type */
	uint8_t fixed_len;	/*!< length in case of \ref TLV_TYPE_FIXED */
};

/*! Definition of All 256 IE / TLV */
struct tlv_definition {
	struct tlv_def def[256];
};

/*! result of the TLV parser */
struct tlv_parsed {
	struct tlv_p_entry lv[256];
};

extern struct tlv_definition tvlv_att_def;
extern struct tlv_definition vtvlv_gan_att_def;

int tlv_parse_one(uint8_t *o_tag, uint16_t *o_len, const uint8_t **o_val,
                  const struct tlv_definition *def,
                  const uint8_t *buf, int buf_len);
int tlv_parse(struct tlv_parsed *dec, const struct tlv_definition *def,
	      const uint8_t *buf, int buf_len, uint8_t lv_tag, uint8_t lv_tag2);
int tlv_parse2(struct tlv_parsed *dec, int dec_multiples,
	       const struct tlv_definition *def, const uint8_t *buf, int buf_len,
	       uint8_t lv_tag, uint8_t lv_tag2);
/* take a master (src) tlv def and fill up all empty slots in 'dst' */
void tlv_def_patch(struct tlv_definition *dst, const struct tlv_definition *src);

int tlv_encode_one(struct msgb *msg, enum tlv_type type, uint8_t tag,
		   unsigned int len, const uint8_t *val);
int tlv_encode(struct msgb *msg, const struct tlv_definition *def, const struct tlv_parsed *tp);
int tlv_encode_ordered(struct msgb *msg, const struct tlv_definition *def, const struct tlv_parsed *tp,
			const uint8_t *tag_order, unsigned int tag_order_len);

#define TLVP_PRESENT(x, y)	((x)->lv[y].val)
#define TLVP_LEN(x, y)		(x)->lv[y].len
#define TLVP_VAL(x, y)		(x)->lv[y].val

#define TLVP_PRES_LEN(tp, tag, min_len) \
	(TLVP_PRESENT(tp, tag) && TLVP_LEN(tp, tag) >= min_len)

/*! Return pointer to a TLV element if it is present.
 * Usage:
 *   struct tlv_p_entry *e = TVLP_GET(&tp, TAG);
 *   if (!e)
 *         return -ENOENT;
 *   hexdump(e->val, e->len);
 * \param[in] _tp  pointer to \ref tlv_parsed.
 * \param[in] tag  IE tag to return.
 * \returns struct tlv_p_entry pointer, or NULL if not present.
 */
#define TLVP_GET(_tp, tag)	(TLVP_PRESENT(_tp, tag)? &(_tp)->lv[tag] : NULL)

/*! Like TLVP_GET(), but enforcing a minimum val length.
 * \param[in] _tp  pointer to \ref tlv_parsed.
 * \param[in] tag  IE tag to return.
 * \param[in] min_len  Minimum value length in bytes.
 * \returns struct tlv_p_entry pointer, or NULL if not present or too short.
 */
#define TLVP_GET_MINLEN(_tp, tag, min_len) \
	(TLVP_PRES_LEN(_tp, tag, min_len)? &(_tp)->lv[tag] : NULL)

/*! Like TLVP_VAL(), but enforcing a minimum val length.
 * \param[in] _tp  pointer to \ref tlv_parsed.
 * \param[in] tag  IE tag to return.
 * \param[in] min_len  Minimum value length in bytes.
 * \returns const uint8_t pointer to value, or NULL if not present or too short.
 */
#define TLVP_VAL_MINLEN(_tp, tag, min_len) \
	(TLVP_PRES_LEN(_tp, tag, min_len)? (_tp)->lv[tag].val : NULL)


/*! Obtain 1-byte TLV element.
 *  \param[in] tp pointer to \ref tlv_parsed
 *  \param[in] tag the Tag to look for
 *  \param[in] default_val default value to use if tag not available
 *  \returns the 1st byte of value with a given tag or default_val if tag was not found
 */
static inline uint8_t tlvp_val8(const struct tlv_parsed *tp, uint8_t tag, uint8_t default_val)
{
	const uint8_t *res = TLVP_VAL_MINLEN(tp, tag, 1);

	if (res)
		return res[0];

	return default_val;
}

/*! Align given TLV element with 16 bit value to an even address
 *  \param[in] tp pointer to \ref tlv_parsed
 *  \param[in] pos element to return
 *  \returns aligned 16 bit value
 */
static inline uint16_t tlvp_val16_unal(const struct tlv_parsed *tp, int pos)
{
	uint16_t res;
	memcpy(&res, TLVP_VAL(tp, pos), sizeof(res));
	return res;
}

/*! Align given TLV element with 32 bit value to an address that is a multiple of 4
 *  \param[in] tp pointer to \ref tlv_parsed
 *  \param[in] pos element to return
 *  \returns aligned 32 bit value
 */
static inline uint32_t tlvp_val32_unal(const struct tlv_parsed *tp, int pos)
{
	uint32_t res;
	memcpy(&res, TLVP_VAL(tp, pos), sizeof(res));
	return res;
}

/*! Retrieve (possibly unaligned) TLV element and convert to host byte order
 *  \param[in] tp pointer to \ref tlv_parsed
 *  \param[in] pos element to return
 *  \returns aligned 16 bit value in host byte order
 */
static inline uint16_t tlvp_val16be(const struct tlv_parsed *tp, int pos)
{
	return osmo_load16be(TLVP_VAL(tp, pos));
}

/*! Retrieve (possibly unaligned) TLV element and convert to host byte order
 *  \param[in] tp pointer to \ref tlv_parsed
 *  \param[in] pos element to return
 *  \returns aligned 32 bit value in host byte order
 */
static inline uint32_t tlvp_val32be(const struct tlv_parsed *tp, int pos)
{
	return osmo_load32be(TLVP_VAL(tp, pos));
}


struct tlv_parsed *osmo_tlvp_copy(const struct tlv_parsed *tp_orig, void *ctx);
int osmo_tlvp_merge(struct tlv_parsed *dst, const struct tlv_parsed *src);
int osmo_shift_v_fixed(uint8_t **data, size_t *data_len,
		       size_t len, uint8_t **value);
int osmo_match_shift_tv_fixed(uint8_t **data, size_t *data_len,
			      uint8_t tag, size_t len, uint8_t **value);
int osmo_shift_tlv(uint8_t **data, size_t *data_len,
		   uint8_t *tag, uint8_t **value, size_t *value_len);
int osmo_match_shift_tlv(uint8_t **data, size_t *data_len,
		   uint8_t tag, uint8_t **value, size_t *value_len);
int osmo_shift_lv(uint8_t **data, size_t *data_len,
		  uint8_t **value, size_t *value_len);

#define MSG_DEF(name, mand_ies, flags) { name, mand_ies, ARRAY_SIZE(mand_ies), flags }

struct osmo_tlv_prot_msg_def {
	/*! human-readable name of message type (optional) */
	const char *name;
	/*! array of mandatory IEs */
	const uint8_t *mand_ies;
	/*! number of entries in 'mand_ies' above */
	uint8_t mand_count;
	/*! user-defined flags (like uplink/downlink/...) */
	uint32_t flags;
};
struct osmo_tlv_prot_ie_def {
	/*! minimum length of IE value part, in octets */
	uint16_t min_len;
	/*! huamn-readable name (optional) */
	const char *name;
};

/*! Osmocom TLV protocol definition */
struct osmo_tlv_prot_def {
	/*! human-readable name of protocol */
	const char *name;
	/*! TLV parser definition (optional) */
	const struct tlv_definition *tlv_def;
	/*! definition of each message (8-bit message type) */
	struct osmo_tlv_prot_msg_def msg_def[256];
	/*! definition of IE for each 8-bit tag */
	struct osmo_tlv_prot_ie_def ie_def[256];
	/*! value_string array of message type names (legacy, if not populated in msg_def) */
	const struct value_string *msgt_names;
};

const char *osmo_tlv_prot_msg_name(const struct osmo_tlv_prot_def *pdef, uint8_t msg_type);
const char *osmo_tlv_prot_ie_name(const struct osmo_tlv_prot_def *pdef, uint8_t iei);

int osmo_tlv_prot_validate_tp(const struct osmo_tlv_prot_def *pdef, uint8_t msg_type,
			      const struct tlv_parsed *tp, int log_subsys, const char *log_pfx);

int osmo_tlv_prot_parse(const struct osmo_tlv_prot_def *pdef,
			struct tlv_parsed *dec, unsigned int dec_multiples, uint8_t msg_type,
			const uint8_t *buf, unsigned int buf_len, uint8_t lv_tag, uint8_t lv_tag2,
			int log_subsys, const char *log_pfx);

static inline uint32_t osmo_tlv_prot_msgt_flags(const struct osmo_tlv_prot_def *pdef, uint8_t msg_type)
{
	return pdef->msg_def[msg_type].flags;
}


/*! @} */
