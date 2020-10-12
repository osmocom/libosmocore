/* 3GPP TS 23.032 GAD: Universal Geographical Area Description */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <inttypes.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gad.h>

/*! \addtogroup gad
 *  @{
 *  \file gad.c
 *  Message encoding and decoding for 3GPP TS 23.032 GAD: Universal Geographical Area Description.
 */

const struct value_string osmo_gad_type_names[] = {
	{ GAD_TYPE_ELL_POINT, "Ellipsoid-point" },
	{ GAD_TYPE_ELL_POINT_UNC_CIRCLE, "Ellipsoid-point-with-uncertainty-circle" },
	{ GAD_TYPE_ELL_POINT_UNC_ELLIPSE, "Ellipsoid-point-with-uncertainty-ellipse" },
	{ GAD_TYPE_POLYGON, "Polygon" },
	{ GAD_TYPE_ELL_POINT_ALT, "Ellipsoid-point-with-altitude" },
	{ GAD_TYPE_ELL_POINT_ALT_UNC_ELL, "Ellipsoid-point-with-altitude-and-uncertainty-ellipsoid" },
	{ GAD_TYPE_ELL_ARC, "Ellipsoid-arc" },
	{ GAD_TYPE_HA_ELL_POINT_UNC_ELLIPSE, "High-accuracy-ellipsoid-point-with-uncertainty-ellipse" },
	{ GAD_TYPE_HA_ELL_POINT_ALT_UNC_ELL, "High-accuracy-ellipsoid-point-with-altitude-and-uncertainty-ellipsoid" },
	{}
};

/*! Encode a latitude value according to 3GPP TS 23.032.
 * Useful to clamp a latitude to an actually encodable accuracy:
 * set_lat = osmo_gad_dec_lat(osmo_gad_enc_lat(orig_lat));
 * \param[in] deg_1e6  Latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N).
 * \returns encoded latitude in host-byte-order (24bit).
 */
uint32_t osmo_gad_enc_lat(int32_t deg_1e6)
{
	/* N <= ((2**23)/90)*X < N+1
	 * N: encoded latitude
	 * X: latitude in degrees
	 */
	int32_t sign = 0;
	int64_t x;
	deg_1e6 = OSMO_MAX(-90000000, OSMO_MIN(90000000, deg_1e6));
	if (deg_1e6 < 0) {
		sign = 1 << 23;
		deg_1e6 = -deg_1e6;
	}
	x = deg_1e6;
	x <<= 23;
	x += (1 << 23) - 1;
	x /= 90 * 1000000;
	return sign | (x & 0x7fffff);
}

/*! Decode a latitude value according to 3GPP TS 23.032.
 * Useful to clamp a latitude to an actually encodable accuracy:
 * set_lat = osmo_gad_dec_lat(osmo_gad_enc_lat(orig_lat));
 * \param[in] lat  encoded latitude in host-byte-order (24bit).
 * \returns decoded latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N).
 */
int32_t osmo_gad_dec_lat(uint32_t lat)
{
	int64_t sign = 1;
	int64_t x;
	if (lat & 0x800000) {
		sign = -1;
		lat &= 0x7fffff;
	}
	x = lat;
	x *= 90 * 1000000;
	x >>= 23;
	x *= sign;
	return x;
}

/*! Encode a longitude value according to 3GPP TS 23.032.
 * Useful to clamp a longitude to an actually encodable accuracy:
 * set_lon = osmo_gad_dec_lon(osmo_gad_enc_lon(orig_lon));
 * \param[in] deg_1e6  Longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E).
 * \returns encoded longitude in host-byte-order (24bit).
 */
uint32_t osmo_gad_enc_lon(int32_t deg_1e6)
{
	/* -180 .. 180 degrees mapped to a signed 24 bit integer.
	 * N <= ((2**24)/360) * X < N+1
	 * N: encoded longitude
	 * X: longitude in degrees
	 */
	int64_t x;
	deg_1e6 = OSMO_MAX(-180000000, OSMO_MIN(180000000, deg_1e6));
	x = deg_1e6;
	x *= (1 << 24);
	if (deg_1e6 >= 0)
		x += (1 << 24) - 1;
	else
		x -= (1 << 24) - 1;
	x /= 360 * 1000000;
	return (uint32_t)(x & 0xffffff);
}

/*! Decode a longitude value according to 3GPP TS 23.032.
 * Normally, encoding and decoding is done via osmo_gad_enc() and osmo_gad_dec() for entire PDUs. But calling this
 * directly can be useful to clamp a longitude to an actually encodable accuracy:
 * int32_t set_lon = osmo_gad_dec_lon(osmo_gad_enc_lon(orig_lon));
 * \param[in] lon  Encoded longitude.
 * \returns Longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E).
 */
int32_t osmo_gad_dec_lon(uint32_t lon)
{
	/* -180 .. 180 degrees mapped to a signed 24 bit integer.
	 * N <= ((2**24)/360) * X < N+1
	 * N: encoded longitude
	 * X: longitude in degrees
	 */
	int32_t slon;
	int64_t x;
	if (lon & 0x800000) {
		/* make the 24bit negative number to a 32bit negative number */
		slon = lon | 0xff000000;
	} else {
		slon = lon;
	}
	x = slon;
	x *= 360 * 1000000;
	x /= (1 << 24);
	return x;
}

/*
 * r = C((1+x)**K - 1)
 * C = 10, x = 0.1
 *
 * def r(k):
 *     return 10.*(((1+0.1)**k) -1 )
 * for k in range(128):
 *     print('%d,' % (r(k) * 1000.))
 */
static uint32_t table_uncertainty_1e3[128] = {
	0, 1000, 2100, 3310, 4641, 6105, 7715, 9487, 11435, 13579, 15937, 18531, 21384, 24522, 27974, 31772, 35949,
	40544, 45599, 51159, 57274, 64002, 71402, 79543, 88497, 98347, 109181, 121099, 134209, 148630, 164494, 181943,
	201137, 222251, 245476, 271024, 299126, 330039, 364043, 401447, 442592, 487851, 537636, 592400, 652640, 718904,
	791795, 871974, 960172, 1057189, 1163908, 1281299, 1410429, 1552472, 1708719, 1880591, 2069650, 2277615,
	2506377, 2758014, 3034816, 3339298, 3674227, 4042650, 4447915, 4893707, 5384077, 5923485, 6516834, 7169517,
	7887469, 8677216, 9545938, 10501531, 11552685, 12708953, 13980849, 15379933, 16918927, 18611820, 20474002,
	22522402, 24775642, 27254206, 29980627, 32979690, 36278659, 39907525, 43899277, 48290205, 53120226, 58433248,
	64277573, 70706330, 77777964, 85556760, 94113436, 103525780, 113879358, 125268293, 137796123, 151576735,
	166735409, 183409950, 201751945, 221928139, 244121953, 268535149, 295389664, 324929630, 357423593, 393166952,
	432484648, 475734112, 523308524, 575640376, 633205414, 696526955, 766180651, 842799716, 927080688, 1019789756,
	1121769732, 1233947705, 1357343476, 1493078824, 1642387706, 1806627477,
};

/*! Decode an uncertainty circle value according to 3GPP TS 23.032.
 * Useful to clamp a value to an actually encodable accuracy:
 * set_unc = osmo_gad_dec_unc(osmo_gad_enc_unc(orig_unc));
 * \param[in] unc  Encoded uncertainty value.
 * \returns Uncertainty value in millimeters.
 */
uint32_t osmo_gad_dec_unc(uint8_t unc)
{
	return table_uncertainty_1e3[unc & 0x7f];
}

/*! Encode an uncertainty circle value according to 3GPP TS 23.032.
 * Normally, encoding and decoding is done via osmo_gad_enc() and osmo_gad_dec() for entire PDUs. But calling this
 * directly can be useful to clamp a value to an actually encodable accuracy:
 * uint32_t set_unc = osmo_gad_dec_unc(osmo_gad_enc_unc(orig_unc));
 * \param[in] mm  Uncertainty value in millimeters.
 * \returns  Encoded uncertainty value.
 */
uint8_t osmo_gad_enc_unc(uint32_t mm)
{
	uint8_t unc;
	for (unc = 0; unc < ARRAY_SIZE(table_uncertainty_1e3); unc++) {
		if (table_uncertainty_1e3[unc] > mm)
			return unc - 1;
	}
	return 127;
}

/* So far we don't encode a high-accuracy uncertainty anywhere, so these static items would flag as compiler warnings
 * for unused items. As soon as any HA items get used, remove this ifdef. */
#ifdef GAD_FUTURE

/*
 * r = C((1+x)**K - 1)
 * C = 0.3, x = 0.02
 *
 * def r(k):
 *     return 0.3*(((1+0.02)**k) -1 )
 * for k in range(256):
 *     print('%d,' % (r(k) * 1000.))
 */
static uint32_t table_ha_uncertainty_1e3[256] = {
	0, 6, 12, 18, 24, 31, 37, 44, 51, 58, 65, 73, 80, 88, 95, 103, 111, 120, 128, 137, 145, 154, 163, 173, 182, 192,
	202, 212, 222, 232, 243, 254, 265, 276, 288, 299, 311, 324, 336, 349, 362, 375, 389, 402, 417, 431, 445, 460,
	476, 491, 507, 523, 540, 556, 574, 591, 609, 627, 646, 665, 684, 703, 724, 744, 765, 786, 808, 830, 853, 876,
	899, 923, 948, 973, 998, 1024, 1051, 1078, 1105, 1133, 1162, 1191, 1221, 1252, 1283, 1314, 1347, 1380, 1413,
	1447, 1482, 1518, 1554, 1592, 1629, 1668, 1707, 1748, 1788, 1830, 1873, 1916, 1961, 2006, 2052, 2099, 2147,
	2196, 2246, 2297, 2349, 2402, 2456, 2511, 2567, 2625, 2683, 2743, 2804, 2866, 2929, 2994, 3060, 3127, 3195,
	3265, 3336, 3409, 3483, 3559, 3636, 3715, 3795, 3877, 3961, 4046, 4133, 4222, 4312, 4404, 4498, 4594, 4692,
	4792, 4894, 4998, 5104, 5212, 5322, 5435, 5549, 5666, 5786, 5907, 6032, 6158, 6287, 6419, 6554, 6691, 6830,
	6973, 7119, 7267, 7418, 7573, 7730, 7891, 8055, 8222, 8392, 8566, 8743, 8924, 9109, 9297, 9489, 9685, 9884,
	10088, 10296, 10508, 10724, 10944, 11169, 11399, 11633, 11871, 12115, 12363, 12616, 12875, 13138, 13407, 13681,
	13961, 14246, 14537, 14834, 15136, 15445, 15760, 16081, 16409, 16743, 17084, 17431, 17786, 18148, 18517, 18893,
	19277, 19669, 20068, 20475, 20891, 21315, 21747, 22188, 22638, 23096, 23564, 24042, 24529, 25025, 25532, 26048,
	26575, 27113, 27661, 28220, 28791, 29372, 29966, 30571, 31189, 31818, 32461, 33116, 33784, 34466, 35161, 35871,
	36594, 37332, 38085, 38852, 39635, 40434, 41249, 42080, 42927, 43792, 44674, 45573, 46491,
};

static uint32_t osmo_gad_dec_ha_unc(uint8_t unc)
{
	return table_uncertainty_1e3[unc];
}

static uint8_t osmo_gad_enc_ha_unc(uint32_t mm)
{
	uint8_t unc;
	for (unc = 0; unc < ARRAY_SIZE(table_ha_uncertainty_1e3); unc++) {
		if (table_uncertainty_1e3[unc] > mm)
			return unc - 1;
	}
	return 255;
}

#endif /* GAD_FUTURE */

/* Return error code, and, if required, allocate and populate struct osmo_gad_err. */
#define DEC_ERR(RC, TYPE, fmt, args...) do { \
		if (err) { \
			*err = talloc_zero(err_ctx, struct osmo_gad_err); \
			**err = (struct osmo_gad_err){ \
				.rc = (RC), \
				.type = (TYPE), \
				.logmsg = talloc_asprintf(*err, "Error decoding GAD%s%s: " fmt, \
							  ((int)(TYPE)) >= 0 ? " " : "", \
							  ((int)(TYPE)) >= 0 ? osmo_gad_type_name(TYPE) : "", ##args), \
			}; \
		} \
		return RC; \
	} while(0)

static int osmo_gad_enc_ell_point_unc_circle(struct gad_raw_ell_point_unc_circle *raw, const struct osmo_gad_ell_point_unc_circle *v)
{
	if (v->lat < -90000000 || v->lat > 90000000)
		return -EINVAL;
	if (v->lon < -180000000 || v->lon > 180000000)
		return -EINVAL;
	*raw = (struct gad_raw_ell_point_unc_circle){
		.h = { .type = GAD_TYPE_ELL_POINT_UNC_CIRCLE },
		.unc = osmo_gad_enc_unc(v->unc),
	};
	osmo_store32be_ext(osmo_gad_enc_lat(v->lat), raw->lat, 3);
	osmo_store32be_ext(osmo_gad_enc_lon(v->lon), raw->lon, 3);
	return sizeof(raw);
}

static int osmo_gad_dec_ell_point_unc_circle(struct osmo_gad_ell_point_unc_circle *v,
					     struct osmo_gad_err **err, void *err_ctx,
					     const struct gad_raw_ell_point_unc_circle *raw)
{
	/* Load 24bit big endian */
	v->lat = osmo_gad_dec_lat(osmo_load32be_ext_2(raw->lat, 3));
	v->lon = osmo_gad_dec_lon(osmo_load32be_ext_2(raw->lon, 3));

	if (raw->spare2)
		DEC_ERR(-EINVAL, raw->h.type, "Bit 8 of Uncertainty code should be zero");

	v->unc = osmo_gad_dec_unc(raw->unc);
	return 0;
}

static int osmo_gad_raw_len(const union gad_raw *gad_raw)
{
	switch (gad_raw->h.type) {
	case GAD_TYPE_ELL_POINT:
		return sizeof(gad_raw->ell_point);
	case GAD_TYPE_ELL_POINT_UNC_CIRCLE:
		return sizeof(gad_raw->ell_point_unc_circle);
	case GAD_TYPE_ELL_POINT_UNC_ELLIPSE:
		return sizeof(gad_raw->ell_point_unc_ellipse);
	case GAD_TYPE_POLYGON:
		if (gad_raw->polygon.h.num_points < 3)
			return -EINVAL;
		return sizeof(gad_raw->polygon.h)
			+ gad_raw->polygon.h.num_points * sizeof(gad_raw->polygon.point[0]);
	case GAD_TYPE_ELL_POINT_ALT:
		return sizeof(gad_raw->ell_point_alt);
	case GAD_TYPE_ELL_POINT_ALT_UNC_ELL:
		return sizeof(gad_raw->ell_point_alt_unc_ell);
	case GAD_TYPE_ELL_ARC:
		return sizeof(gad_raw->ell_arc);
	case GAD_TYPE_HA_ELL_POINT_UNC_ELLIPSE:
		return sizeof(gad_raw->ha_ell_point_unc_ell);
	case GAD_TYPE_HA_ELL_POINT_ALT_UNC_ELL:
		return sizeof(gad_raw->ha_ell_point_alt_unc_ell);
	default:
		return -ENOTSUP;
	}
}

/*! Append a GAD PDU to the msgb.
 * Write the correct number of bytes depending on the GAD type and possibly on variable length attributes.
 * \param[out] msg  Append to this msgb.
 * \param[in] gad_raw  GAD data to write.
 * \returns number of bytes appended to msgb, or negative on failure.
 */
int osmo_gad_raw_write(struct msgb *msg, const union gad_raw *gad_raw)
{
	int len;
	uint8_t *dst;
	len = osmo_gad_raw_len(gad_raw);
	if (len < 0)
		return len;
	dst = msgb_put(msg, len);
	memcpy(dst, (void*)gad_raw, len);
	return len;
}

/*! Read a GAD PDU and validate structure.
 * Memcpy from data to gad_raw struct, and validate correct length depending on the GAD type and possibly on variable
 * length attributes.
 * \param[out] gad_raw  Copy GAD PDU here.
 * \param[out] err  Returned pointer to error info, dynamically allocated; NULL to not return any.
 * \param[in] err_ctx  Talloc context to allocate err from, if required.
 * \param[in] data  Encoded GAD bytes buffer.
 * \param[in] len  Length of data in bytes.
 * \returns 0 on success, negative on error. If returning negative and err was non-NULL, *err is guaranteed to point to
 *          an allocated struct osmo_gad_err.
 */
int osmo_gad_raw_read(union gad_raw *gad_raw, struct osmo_gad_err **err, void *err_ctx, const uint8_t *data, uint8_t len)
{
	int gad_len;
	const union gad_raw *src;
	if (err)
		*err = NULL;
	if (len < sizeof(src->h))
		DEC_ERR(-EINVAL, -1, "GAD data too short for header (%u bytes)", len);

	src = (void*)data;
	gad_len = osmo_gad_raw_len(src);
	if (gad_len < 0)
		DEC_ERR(-EINVAL, src->h.type, "GAD data invalid (rc=%d)", gad_len);
	if (gad_len != len)
		DEC_ERR(-EINVAL, src->h.type, "GAD data with unexpected length: expected %d bytes, got %u",
			gad_len, len);

	memcpy((void*)gad_raw, data, gad_len);
	return 0;
}

/*! Write GAD values with consistent units to raw GAD PDU representation.
 * \param[out] gad_raw  Write to this buffer.
 * \param[in] gad  GAD values to encode.
 * \returns number of bytes written, or negative on failure.
 */
int osmo_gad_enc(union gad_raw *gad_raw, const struct osmo_gad *gad)
{
	switch (gad->type) {
	case GAD_TYPE_ELL_POINT_UNC_CIRCLE:
		return osmo_gad_enc_ell_point_unc_circle(&gad_raw->ell_point_unc_circle, &gad->ell_point_unc_circle);
	default:
		return -ENOTSUP;
	}
}

/*! Decode GAD raw PDU to values with consistent units.
 * \param[out] gad  Decoded GAD values are written here.
 * \param[out] err  Returned pointer to error info, dynamically allocated; NULL to not return any.
 * \param[in] err_ctx  Talloc context to allocate err from, if required.
 * \param[in] raw  Raw GAD data in network-byte-order.
 * \returns 0 on success, negative on error. If returning negative and err was non-NULL, *err is guaranteed to point to
 *          an allocated struct osmo_gad_err.
 */
int osmo_gad_dec(struct osmo_gad *gad, struct osmo_gad_err **err, void *err_ctx, const union gad_raw *raw)
{
	*gad = (struct osmo_gad){
		.type = raw->h.type,
	};
	switch (raw->h.type) {
	case GAD_TYPE_ELL_POINT_UNC_CIRCLE:
		return osmo_gad_dec_ell_point_unc_circle(&gad->ell_point_unc_circle, err, err_ctx,
							 &raw->ell_point_unc_circle);
	default:
		DEC_ERR(-ENOTSUP, raw->h.type, "unsupported GAD type");
	}
}

/*! Return a human readable representation of a raw GAD PDU.
 * Convert to GAD values and feed the result to osmo_gad_to_str_buf().
 * \param[out] buf  Buffer to write string to.
 * \param[in] buflen  sizeof(buf).
 * \param[in] gad  Location data.
 * \returns number of chars that would be written, like snprintf().
 */
int osmo_gad_raw_to_str_buf(char *buf, size_t buflen, const union gad_raw *raw)
{
	struct osmo_gad gad;
	if (osmo_gad_dec(&gad, NULL, NULL, raw)) {
		struct osmo_strbuf sb = { .buf = buf, .len = buflen };
		OSMO_STRBUF_PRINTF(sb, "invalid");
		return sb.chars_needed;
	}
	return osmo_gad_to_str_buf(buf, buflen, &gad);
}

/*! Return a human readable representation of a raw GAD PDU.
 * Convert to GAD values and feed the result to osmo_gad_to_str_buf().
 * \param[in] ctx  Talloc ctx to allocate string buffer from.
 * \param[in] raw  GAD data in network-byte-order.
 * \returns resulting string, dynamically allocated.
 */
char *osmo_gad_raw_to_str_c(void *ctx, const union gad_raw *raw)
{
	OSMO_NAME_C_IMPL(ctx, 128, "ERROR", osmo_gad_raw_to_str_buf, raw)
}

/*! Return a human readable representation of GAD (location estimate) values.
 * \param[out] buf  Buffer to write string to.
 * \param[in] buflen  sizeof(buf).
 * \param[in] gad  Location data.
 * \returns number of chars that would be written, like snprintf().
 */
int osmo_gad_to_str_buf(char *buf, size_t buflen, const struct osmo_gad *gad)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	if (!gad) {
		OSMO_STRBUF_PRINTF(sb, "null");
		return sb.chars_needed;
	}

	OSMO_STRBUF_PRINTF(sb, "%s{", osmo_gad_type_name(gad->type));

	switch (gad->type) {
	case GAD_TYPE_ELL_POINT:
		OSMO_STRBUF_PRINTF(sb, "lat=");
		OSMO_STRBUF_APPEND(sb, osmo_int_to_float_str_buf, gad->ell_point.lat, 6);
		OSMO_STRBUF_PRINTF(sb, ",lon=");
		OSMO_STRBUF_APPEND(sb, osmo_int_to_float_str_buf, gad->ell_point.lon, 6);
		break;

	case GAD_TYPE_ELL_POINT_UNC_CIRCLE:
		OSMO_STRBUF_PRINTF(sb, "lat=");
		OSMO_STRBUF_APPEND(sb, osmo_int_to_float_str_buf, gad->ell_point_unc_circle.lat, 6);
		OSMO_STRBUF_PRINTF(sb, ",lon=");
		OSMO_STRBUF_APPEND(sb, osmo_int_to_float_str_buf, gad->ell_point_unc_circle.lon, 6);
		OSMO_STRBUF_PRINTF(sb, ",unc=");
		OSMO_STRBUF_APPEND(sb, osmo_int_to_float_str_buf, gad->ell_point_unc_circle.unc, 3);
		OSMO_STRBUF_PRINTF(sb, "m");
		break;

	default:
		OSMO_STRBUF_PRINTF(sb, "to-str-not-implemented");
		break;
	}

	OSMO_STRBUF_PRINTF(sb, "}");
	return sb.chars_needed;
}

/*! Return a human readable representation of GAD (location estimate) values.
 * \param[in] ctx  Talloc ctx to allocate string buffer from.
 * \param[in] val  Value to convert to float.
 * \returns resulting string, dynamically allocated.
 */
char *osmo_gad_to_str_c(void *ctx, const struct osmo_gad *gad)
{
	OSMO_NAME_C_IMPL(ctx, 128, "ERROR", osmo_gad_to_str_buf, gad)
}

/*! @} */
