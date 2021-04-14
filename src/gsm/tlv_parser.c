/* (C) 2008-2020 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2017 by sysmocom - s.f.m.c. GmbH
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/tlv.h>

/*! \addtogroup tlv
 *  @{
 *  Osmocom TLV Parser
 *
 *  The Osmocom TLV parser is intended to operate as a low-level C
 *  implementation without dynamic memory allocations.  Basically, it
 *  iterates over the IE (Information Elements) of the message and fills
 *  an array of pointers, indexed by the IEI (IE Identifier).  The
 *  parser output is thus an array of pointers to the start of the
 *  respective IE inside the message.
 *
 *  The TLV parser is configured by a TLV parser definition, which
 *  determines which if the IEIs for a given protocol are of which
 *  particular type.  Types are e.g. TV (Tag + single byte value), Tag +
 *  fixed-length value, TLV with 8bit length, TLV with 16bit length, TLV
 *  with variable-length length field, etc.
 *
 * \file tlv_parser.c */

struct tlv_definition tvlv_att_def;
struct tlv_definition vtvlv_gan_att_def;

/*! Dump parsed TLV structure to stdout */
int tlv_dump(struct tlv_parsed *dec)
{
	int i;

	for (i = 0; i <= 0xff; i++) {
		if (!dec->lv[i].val)
			continue;
		printf("T=%02x L=%d\n", i, dec->lv[i].len);
	}
	return 0;
}

/*! Copy \ref tlv_parsed using given talloc context
 *  \param[in] tp_orig Parsed TLV structure
 *  \param[in] ctx Talloc context for allocations
 *  \returns NULL on errors, \ref tlv_parsed pointer otherwise
 */
struct tlv_parsed *osmo_tlvp_copy(const struct tlv_parsed *tp_orig, void *ctx)
{
	struct tlv_parsed *tp_out;
	size_t i, len;

	tp_out = talloc_zero(ctx, struct tlv_parsed);
	if (!tp_out)
		return NULL;

	/* if the original is NULL, return empty tlvp */
	if (!tp_orig)
		return tp_out;

	for (i = 0; i < ARRAY_SIZE(tp_orig->lv); i++) {
		len = tp_orig->lv[i].len;
		tp_out->lv[i].len = len;
		if (len && tp_out->lv[i].val) {
			tp_out->lv[i].val = talloc_zero_size(tp_out, len);
			if (!tp_out->lv[i].val) {
				talloc_free(tp_out);
				return NULL;
			}
			memcpy((uint8_t *)tp_out->lv[i].val, tp_orig->lv[i].val,
			       len);
		}
	}

	return tp_out;
}

/*! Merge all \ref tlv_parsed attributes of 'src' into 'dst'
 *  \param[in] dst Parsed TLV structure to merge into
 *  \param[in] src Parsed TLV structure to merge from
 *  \returns 0 on success, negative on error
 */
int osmo_tlvp_merge(struct tlv_parsed *dst, const struct tlv_parsed *src)
{
	size_t i, len;
	for (i = 0; i < ARRAY_SIZE(dst->lv); i++) {
		len = src->lv[i].len;
		if (len == 0 || src->lv[i].val == NULL)
			continue;
		if (dst->lv[i].val) {
			talloc_free((uint8_t *) dst->lv[i].val);
			dst->lv[i].len = 0;
		}
		dst->lv[i].val = talloc_zero_size(dst, len);
		if (!dst->lv[i].val)
			return -ENOMEM;
		memcpy((uint8_t *) dst->lv[i].val, src->lv[i].val, len);
	}
	return 0;
}


/*! Encode a single TLV into given message buffer
 *  \param[inout] msg Caller-allocated message buffer with sufficient tailroom
 *  \param[in] type TLV type/format to use during encode
 *  \param[in] tag Tag of TLV to be encoded
 *  \parma[in] len Length of TLV to be encoded
 *  \param[in] val Value part of TLV to be encoded
 *  \returns 0 on success; negative in case of error */
int tlv_encode_one(struct msgb *msg, enum tlv_type type, uint8_t tag,
		   unsigned int len, const uint8_t *val)
{
	switch (type) {
	case TLV_TYPE_NONE:
		break;
	case TLV_TYPE_FIXED:
		msgb_tv_fixed_put(msg, tag, len, val);
		break;
	case TLV_TYPE_T:
		msgb_v_put(msg, tag);
		break;
	case TLV_TYPE_TV:
		msgb_tv_put(msg, tag, val[0]);
		break;
	case TLV_TYPE_TLV:
		msgb_tlv_put(msg, tag, len, val);
		break;
	case TLV_TYPE_TL16V:
		msgb_tl16v_put(msg, tag, len, val);
		break;
	case TLV_TYPE_TvLV:
		msgb_tvlv_put(msg, tag, len, val);
		break;
	case TLV_TYPE_SINGLE_TV:
		msgb_v_put(msg, (tag << 4) | (val[0] & 0xf));
		break;
	case TLV_TYPE_vTvLV_GAN:
		msgb_vtvlv_gan_put(msg, tag, len, val);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*! Encode a set of decoded TLVs according to a given definition into a message buffer
 *  \param[inout] msg Caller-allocated message buffer with sufficient tailroom
 *  \param[in] def structure defining the valid TLV tags / configurations
 *  \param[in] tp decoded values to be encoded
 *  \returns number of bytes consumed in msg; negative in case of error */
int tlv_encode(struct msgb *msg, const struct tlv_definition *def, const struct tlv_parsed *tp)
{
	unsigned int tailroom_before = msgb_tailroom(msg);
	unsigned int i;
	int rc;

	for (i = 0; i < ARRAY_SIZE(tp->lv); i++) {
		/* skip entries in the array that aren't used/filled */
		if (!TLVP_PRESENT(tp, i))
			continue;

		rc = tlv_encode_one(msg, def->def[i].type, i, TLVP_LEN(tp, i), TLVP_VAL(tp, i));
		if (rc < 0)
			return rc;
	}

	return tailroom_before - msgb_tailroom(msg);
}

/*! Encode a set of decoded TLVs according to a given definition and IE order into a message buffer
 *  \param[inout] msg Caller-allocated message buffer with sufficient tailroom
 *  \param[in] def structure defining the valid TLV tags / configurations
 *  \param[in] tp decoded values to be encoded
 *  \param[in] tag_order array of tags determining the IE encoding order
 *  \param[in] tag_order_len length of tag_order
 *  \returns number of bytes consumed in msg; negative in case of error */
int tlv_encode_ordered(struct msgb *msg, const struct tlv_definition *def, const struct tlv_parsed *tp,
			const uint8_t *tag_order, unsigned int tag_order_len)
{

	unsigned int tailroom_before = msgb_tailroom(msg);
	unsigned int i;
	int rc;

	for (i = 0; i < tag_order_len; i++) {
		uint8_t tag = tag_order[i];

		/* skip entries in the array that aren't used/filled */
		if (!TLVP_PRESENT(tp, tag))
			continue;

		rc = tlv_encode_one(msg, def->def[tag].type, tag, TLVP_LEN(tp, tag), TLVP_VAL(tp, tag));
		if (rc < 0)
			return rc;
	}
	return tailroom_before - msgb_tailroom(msg);
}

/*! Parse a single TLV encoded IE
 *  \param[out] o_tag the tag of the IE that was found
 *  \param[out] o_len length of the IE that was found
 *  \param[out] o_val pointer to the data of the IE that was found
 *  \param[in] def structure defining the valid TLV tags / configurations
 *  \param[in] buf the input data buffer to be parsed
 *  \param[in] buf_len length of the input data buffer
 *  \returns number of bytes consumed by the TLV entry / IE parsed; negative in case of error
 */
int tlv_parse_one(uint8_t *o_tag, uint16_t *o_len, const uint8_t **o_val,
		  const struct tlv_definition *def,
		  const uint8_t *buf, int buf_len)
{
	uint8_t tag;
	int len; /* number of bytes consumed by TLV entry */

	if (buf_len < 1)
		return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;

	tag = *buf;
	*o_tag = tag;

	/* single octet TV IE */
	if (def->def[tag & 0xf0].type == TLV_TYPE_SINGLE_TV) {
		*o_tag = tag & 0xf0;
		*o_val = buf;
		*o_len = 1;
		return 1;
	}

	/* FIXME: use tables for known IEI */
	switch (def->def[tag].type) {
	case TLV_TYPE_T:
		/* GSM TS 04.07 11.2.4: Type 1 TV or Type 2 T */
		*o_val = buf;
		*o_len = 0;
		len = 1;
		break;
	case TLV_TYPE_TV:
		*o_val = buf+1;
		*o_len = 1;
		len = 2;
		break;
	case TLV_TYPE_FIXED:
		*o_val = buf+1;
		*o_len = def->def[tag].fixed_len;
		len = def->def[tag].fixed_len + 1;
		break;
	case TLV_TYPE_TLV:
tlv:		/* GSM TS 04.07 11.2.4: Type 4 TLV */
		if (buf_len < 2)
			return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
		*o_val = buf+2;
		*o_len = *(buf+1);
		len = *o_len + 2;
		break;
	case TLV_TYPE_vTvLV_GAN:	/* 44.318 / 11.1.4 */
		/* FIXME: variable-length TAG! */
		if (buf_len < 2)
			return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
		if (*(buf+1) & 0x80) {
			if (buf_len < 3)
				return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
			/* like TL16Vbut without highest bit of len */
			*o_val = buf+3;
			*o_len = (*(buf+1) & 0x7F) << 8 | *(buf+2);
			len = *o_len + 3;
		} else {
			/* like TLV */
			goto tlv;
		}
		break;
	case TLV_TYPE_TvLV:
		if (buf_len < 2)
			return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
		if (*(buf+1) & 0x80) {
			/* like TLV, but without highest bit of len */
			*o_val = buf+2;
			*o_len = *(buf+1) & 0x7f;
			len = *o_len + 2;
			break;
		}
		/* like TL16V, fallthrough */
	case TLV_TYPE_TL16V:
		if (buf_len < 3)
			return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
		*o_val = buf+3;
		*o_len = *(buf+1) << 8 | *(buf+2);
		len = *o_len + 3;
		break;
	default:
		return OSMO_TLVP_ERR_UNKNOWN_TLV_TYPE;
	}

	if (buf_len < len) {
		*o_val = NULL;
		return OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER;
	}
	return len;
}

/*! Parse an entire buffer of TLV encoded Information Elements.
 * In case of multiple occurences of an IE, keep only the first occurence.
 * Most GSM related protocols clearly indicate that in case of duplicate
 * IEs, only the first occurrence shall be used, while any further occurrences
 * shall be ignored.  See e.g. 3GPP TS 24.008 Section 8.6.3.
 * For multiple occurences, use tlv_parse2().
 *  \param[out] dec caller-allocated pointer to \ref tlv_parsed
 *  \param[in] def structure defining the valid TLV tags / configurations
 *  \param[in] buf the input data buffer to be parsed
 *  \param[in] buf_len length of the input data buffer
 *  \param[in] lv_tag an initial LV tag at the start of the buffer
 *  \param[in] lv_tag2 a second initial LV tag following the \a lv_tag
 *  \returns number of TLV entries parsed; negative in case of error
 */
int tlv_parse(struct tlv_parsed *dec, const struct tlv_definition *def,
	      const uint8_t *buf, int buf_len, uint8_t lv_tag,
	      uint8_t lv_tag2)
{
	return tlv_parse2(dec, 1, def, buf, buf_len, lv_tag, lv_tag2);
}

/*! Like tlv_parse(), but capable of decoding multiple occurences of the same IE.
 * Parse an entire buffer of TLV encoded Information Elements.
 * To decode multiple occurences of IEs, provide in dec an _array_ of tlv_parsed, and
 * pass the size of that array in dec_multiples. The first occurence of each IE
 * is stored in dec[0], the second in dec[1] and so forth. If there are more
 * occurences than the array length given in dec_multiples, the remaining
 * occurences are dropped.
 *  \param[out] dec caller-allocated pointer to \ref tlv_parsed
 *  \param[in] dec_multiples length of the tlv_parsed[] in \a dec.
 *  \param[in] def structure defining the valid TLV tags / configurations
 *  \param[in] buf the input data buffer to be parsed
 *  \param[in] buf_len length of the input data buffer
 *  \param[in] lv_tag an initial LV tag at the start of the buffer
 *  \param[in] lv_tag2 a second initial LV tag following the \a lv_tag
 *  \returns number of TLV entries parsed; negative in case of error
 */
int tlv_parse2(struct tlv_parsed *dec, int dec_multiples,
	       const struct tlv_definition *def, const uint8_t *buf, int buf_len,
	       uint8_t lv_tag, uint8_t lv_tag2)
{
	int ofs = 0, num_parsed = 0;
	uint16_t len;
	int dec_i;

	for (dec_i = 0; dec_i < dec_multiples; dec_i++)
		memset(&dec[dec_i], 0, sizeof(*dec));

	if (lv_tag) {
		const uint8_t *val;
		uint16_t parsed_len;
		if (ofs > buf_len)
			return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
		val = &buf[ofs+1];
		len = buf[ofs];
		parsed_len = len + 1;
		if (ofs + parsed_len > buf_len)
			return OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER;
		num_parsed++;
		ofs += parsed_len;
		/* store the resulting val and len */
		for (dec_i = 0; dec_i < dec_multiples; dec_i++) {
			if (dec[dec_i].lv[lv_tag].val != NULL)
				continue;
			dec->lv[lv_tag].val = val;
			dec->lv[lv_tag].len = len;
			break;
		}
	}
	if (lv_tag2) {
		const uint8_t *val;
		uint16_t parsed_len;
		if (ofs > buf_len)
			return OSMO_TLVP_ERR_OFS_BEYOND_BUFFER;
		val = &buf[ofs+1];
		len = buf[ofs];
		parsed_len = len + 1;
		if (ofs + parsed_len > buf_len)
			return OSMO_TLVP_ERR_OFS_LEN_BEYOND_BUFFER;
		num_parsed++;
		ofs += parsed_len;
		/* store the resulting val and len */
		for (dec_i = 0; dec_i < dec_multiples; dec_i++) {
			if (dec[dec_i].lv[lv_tag2].val != NULL)
				continue;
			dec->lv[lv_tag2].val = val;
			dec->lv[lv_tag2].len = len;
			break;
		}
	}

	while (ofs < buf_len) {
		int rv;
		uint8_t tag;
		const uint8_t *val;

		rv = tlv_parse_one(&tag, &len, &val, def,
		                   &buf[ofs], buf_len-ofs);
		if (rv < 0)
			return rv;
		for (dec_i = 0; dec_i < dec_multiples; dec_i++) {
			if (dec[dec_i].lv[tag].val != NULL)
				continue;
			dec[dec_i].lv[tag].val = val;
			dec[dec_i].lv[tag].len = len;
			break;
		}
		ofs += rv;
		num_parsed++;
	}
	//tlv_dump(dec);
	return num_parsed;
}

/*! take a master (src) tlv_definition and fill up all empty slots in 'dst'
 *  \param dst TLV parser definition that is to be patched
 *  \param[in] src TLV parser definition whose content is patched into \a dst */
void tlv_def_patch(struct tlv_definition *dst, const struct tlv_definition *src)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dst->def); i++) {
		if (src->def[i].type == TLV_TYPE_NONE)
			continue;
		if (dst->def[i].type == TLV_TYPE_NONE)
			dst->def[i] = src->def[i];
	}
}

static __attribute__((constructor)) void on_dso_load_tlv(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(tvlv_att_def.def); i++)
		tvlv_att_def.def[i].type = TLV_TYPE_TvLV;

	for (i = 0; i < ARRAY_SIZE(vtvlv_gan_att_def.def); i++)
		vtvlv_gan_att_def.def[i].type = TLV_TYPE_vTvLV_GAN;
}

/*! Advance the data pointer, subtract length and assign value pointer
 *  \param data pointer to the pointer to data
 *  \param data_len pointer to size_t containing \arg data length
 *  \param[in] len the length that we expect the fixed IE to hav
 *  \param[out] value pointer to pointer of value part of IE
 *  \returns length of IE value; negative in case of error
 */
int osmo_shift_v_fixed(uint8_t **data, size_t *data_len,
			size_t len, uint8_t **value)
{
	if (len > *data_len)
		goto fail;

	if (value)
		*value = *data;

	*data += len;
	*data_len -= len;

	return len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

/*! Match tag, check length and assign value pointer
 *  \param data pointer to the pointer to data
 *  \param data_len pointer to size_t containing \arg data length
 *  \param[in] tag the tag (IEI) that we expect at \arg data
 *  \param[in] len the length that we expect the fixed IE to have
 *  \param[out] value pointer to pointer of value part of IE
 *  \returns length of IE value; negative in case of error
 */
int osmo_match_shift_tv_fixed(uint8_t **data, size_t *data_len,
			      uint8_t tag, size_t len,
			      uint8_t **value)
{
	size_t ie_len;

	if (*data_len == 0)
		goto fail;

	if ((*data)[0] != tag)
		return 0;

	if (len > *data_len - 1)
		goto fail;

	if (value)
		*value = *data + 1;

	ie_len = len + 1;
	*data += ie_len;
	*data_len -= ie_len;

	return ie_len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

/*! Verify TLV header and advance data / subtract length
 *  \param data pointer to the pointer to data
 *  \param data_len pointer to size_t containing \arg data length
 *  \param[in] expected_tag the tag (IEI) that we expect at \arg data
 *  \param[out] value pointer to pointer of value part of IE
 *  \param[out] value_len pointer to length of \arg value
 *  \returns length of IE value; negative in case of error
 */
int osmo_match_shift_tlv(uint8_t **data, size_t *data_len,
			 uint8_t expected_tag, uint8_t **value,
			 size_t *value_len)
{
	int rc;
	uint8_t tag;
	uint8_t *old_data = *data;
	size_t old_data_len = *data_len;

	rc = osmo_shift_tlv(data, data_len, &tag, value, value_len);

	if (rc > 0 && tag != expected_tag) {
		*data = old_data;
		*data_len = old_data_len;
		return 0;
	}

	return rc;
}

/*! Extract TLV and advance data pointer + subtract length
 *  \param data pointer to the pointer to data
 *  \param data_len  pointer to size_t containing \arg data lengt
 *  \param[out] tag extract the tag (IEI) at start of \arg data
 *  \param[out] value extracted pointer to value part of TLV
 *  \param[out] value_len extracted length of \arg value
 *  \returns number of bytes subtracted
 */
int osmo_shift_tlv(uint8_t **data, size_t *data_len,
	      uint8_t *tag, uint8_t **value, size_t *value_len)
{
	size_t len;
	size_t ie_len;

	if (*data_len < 2)
		goto fail;

	len = (*data)[1];
	if (len > *data_len - 2)
		goto fail;

	if (tag)
		*tag = (*data)[0];
	if (value)
		*value = *data + 2;
	if (value_len)
		*value_len = len;

	ie_len = len + 2;

	*data += ie_len;
	*data_len -= ie_len;

	return ie_len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

/*! Extract LV and advance data pointer + subtract length
 *  \param data pointer to the pointer to data
 *  \param data_len  pointer to size_t containing \arg data lengt
 *  \param[out] value extracted pointer to value part of TLV
 *  \param[out] value_len extracted length of \arg value
 *  \returns number of bytes subtracted
 */
int osmo_shift_lv(uint8_t **data, size_t *data_len,
		  uint8_t **value, size_t *value_len)
{
	size_t len;
	size_t ie_len;

	if (*data_len < 1)
		goto fail;

	len = (*data)[0];
	if (len > *data_len - 1)
		goto fail;

	if (value)
		*value = *data + 1;
	if (value_len)
		*value_len = len;

	ie_len = len + 1;
	*data += ie_len;
	*data_len -= ie_len;

	return ie_len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

static __thread char ienamebuf[32];
static __thread char msgnamebuf[32];

/*! get the message name for given msg_type in protocol pdef */
const char *osmo_tlv_prot_msg_name(const struct osmo_tlv_prot_def *pdef, uint8_t msg_type)
{
	if (pdef->msg_def[msg_type].name) {
		return pdef->msg_def[msg_type].name;
	} else if (pdef->msgt_names) {
		return get_value_string(pdef->msgt_names, msg_type);
	} else {
		snprintf(msgnamebuf, sizeof(msgnamebuf), "Unknown msg_type 0x%02x", msg_type);
		return msgnamebuf;
	}
}

/*! get the IE name for given IEI in protocol pdef */
const char *osmo_tlv_prot_ie_name(const struct osmo_tlv_prot_def *pdef, uint8_t iei)
{
	if (pdef->ie_def[iei].name) {
		return pdef->ie_def[iei].name;
	} else {
		snprintf(ienamebuf, sizeof(ienamebuf), "Unknown IEI 0x%02x", iei);
		return ienamebuf;
	}
}

/*! Validate an already TLV-decoded message against the protocol definition.
 *  \param[in] pdef protocol definition of given protocol
 *  \param[in] msg_type message type of the parsed message
 *  \param[in] tp TLV parser result
 *  \param[in] log_subsys logging sub-system for log messages
 *  \param[in] log_pfx prefix for log messages
 *  \returns 0 in case of success; negative osmo_tlv_parser_error in case of error
 */
int osmo_tlv_prot_validate_tp(const struct osmo_tlv_prot_def *pdef, uint8_t msg_type,
			      const struct tlv_parsed *tp, int log_subsys, const char *log_pfx)
{
	const struct osmo_tlv_prot_msg_def *msg_def= &pdef->msg_def[msg_type];
	unsigned int err = 0;
	unsigned int i;

	if (msg_def->mand_ies) {
		for (i = 0; i < msg_def->mand_count; i++) {
			uint8_t iei = msg_def->mand_ies[i];
			if (!TLVP_PRESENT(tp, iei)) {
				LOGP(log_subsys, LOGL_ERROR, "%s %s %s: Missing Mandatory IE: %s\n",
				     log_pfx, pdef->name, osmo_tlv_prot_msg_name(pdef, msg_type),
				     osmo_tlv_prot_ie_name(pdef, iei));
				if (!err)
					err = OSMO_TLVP_ERR_MAND_IE_MISSING;
			}
		}
	}

	for (i = 0; i < ARRAY_SIZE(tp->lv); i++) {
		uint16_t min_len;

		if (!TLVP_PRESENT(tp, i))
			continue;

		min_len = pdef->ie_def[i].min_len;
		if (TLVP_LEN(tp, i) < min_len) {
			LOGP(log_subsys, LOGL_ERROR, "%s %s %s: Short IE %s: %u < %u\n", log_pfx,
			     pdef->name, osmo_tlv_prot_msg_name(pdef, msg_type),
			     osmo_tlv_prot_ie_name(pdef, i), TLVP_LEN(tp, i), min_len);
			if (!err)
				err = OSMO_TLVP_ERR_IE_TOO_SHORT;
		}
	}

	return err;
}

/*! Parse + Validate a TLV-encoded message against the protocol definition.
 *  \param[in] pdef protocol definition of given protocol
 *  \param[out] dec caller-allocated pointer to \ref tlv_parsed
 *  \param[in] dec_multiples length of the tlv_parsed[] in \a dec.
 *  \param[in] msg_type message type of the parsed message
 *  \param[in] buf the input data buffer to be parsed
 *  \param[in] buf_len length of the input data buffer
 *  \param[in] lv_tag an initial LV tag at the start of the buffer
 *  \param[in] lv_tag2 a second initial LV tag following the \a lv_tag
 *  \param[in] log_subsys logging sub-system for log messages
 *  \param[in] log_pfx prefix for log messages
 *  \returns 0 in case of success; negative osmo_tlv_parser_error in case of error
 */
int osmo_tlv_prot_parse(const struct osmo_tlv_prot_def *pdef,
			struct tlv_parsed *dec, unsigned int dec_multiples, uint8_t msg_type,
			const uint8_t *buf, unsigned int buf_len, uint8_t lv_tag, uint8_t lv_tag2,
			int log_subsys, const char *log_pfx)
{
	int rc;

	rc = tlv_parse2(dec, dec_multiples, pdef->tlv_def, buf, buf_len, lv_tag, lv_tag2);
	if (rc < 0) {
		LOGP(log_subsys, LOGL_ERROR, "%s %s %s: TLV parser error %d\n", log_pfx,
		     pdef->name, osmo_tlv_prot_msg_name(pdef, msg_type), rc);
		return rc;
	}

	return osmo_tlv_prot_validate_tp(pdef, msg_type, dec, log_subsys, log_pfx);
}

/*! @} */
