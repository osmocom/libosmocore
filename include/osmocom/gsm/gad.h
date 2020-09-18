/*! \addtogroup gad
 *  @{
 *  \file gad.h
 *  Message encoding and decoding for 3GPP TS 23.032 GAD: Universal Geographical Area Description.
 */
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

#pragma once

#include <osmocom/gsm/protocol/gsm_23_032.h>
#include <osmocom/core/utils.h>

struct msgb;

struct osmo_gad_ell_point {
	/*! Latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! Longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
};

struct osmo_gad_ell_point_unc_circle {
	/*! Latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! Longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
	/*! Uncertainty circle radius in millimeters (m * 1e3), 0 .. 18'000'000. */
	uint32_t unc;
};

struct osmo_gad_ell_point_unc_ellipse {
	/*! Latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! Longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
	/*! Uncertainty ellipsoid radius of major axis in millimeters, 0 .. 18'000'000.
	 * Coding of uncertainty is non-linear, use osmo_gad_dec_unc(osmo_gad_enc_unc(val)) to clamp. */
	uint32_t unc_semi_major;
	/*! Uncertainty ellipsoid radius of minor axis in millimeters, 0 .. 18'000'000.
	 * Coding of uncertainty is non-linear, use osmo_gad_dec_unc(osmo_gad_enc_unc(val)) to clamp. */
	uint32_t unc_semi_minor;
	/*! Major axis orientation in degrees (DEG), 0 (N) .. 90 (E) .. 179 (SSE). */
	uint8_t major_ori;
	/*! Confidence in percent, 0 = no information, 1..100%, 101..128 = no information. */
	uint8_t confidence;
};

struct osmo_gad_polygon {
	uint8_t num_points;
	struct osmo_gad_ell_point point[15];
};

struct osmo_gad_ell_point_alt {
	/*! latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
	/*! Altitude in meters, -32767 (depth) .. 32767 (height) */
	int16_t alt;
};

struct osmo_gad_ell_point_alt_unc_ell {
	/*! latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
	/*! Altitude in meters, -32767 (depth) .. 32767 (height) */
	int16_t alt;
	/*! Uncertainty ellipsoid radius of major axis in millimeters, 0 .. 18'000'000.
	 * Coding of uncertainty is non-linear, use osmo_gad_dec_unc(osmo_gad_enc_unc(val)) to clamp. */
	uint32_t unc_semi_major;
	/*! Uncertainty ellipsoid radius of minor axis in millimeters, 0 .. 18'000'000.
	 * Coding of uncertainty is non-linear, use osmo_gad_dec_unc(osmo_gad_enc_unc(val)) to clamp. */
	uint32_t unc_semi_minor;
	/*! Major axis orientation in degrees (DEG), 0 (N) .. 90 (E) .. 179 (SSE). */
	uint8_t major_ori;
	/*! Uncertainty altitude in millimeters, 0 .. 990'000.
	 * Coding of uncertainty altitude is non-linear, and distinct from the non-altitude uncertainty coding. Use
	 * osmo_gad_dec_unc_alt(osmo_gad_enc_unc_alt(val)) to clamp. */
	int32_t unc_alt;
	/*! Confidence in percent, 0 = no information, 1..100%, 101..128 = no information. */
	uint8_t confidence;
};

struct osmo_gad_ell_arc {
	/*! latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
	/*! inner circle radius in mm (m * 1e3) */
	uint32_t inner_r;
	/*! Uncertainty circle radius in millimeters, 0 .. 18'000'000.
	 * Coding of uncertainty is non-linear, use osmo_gad_dec_unc(osmo_gad_enc_unc(val)) to clamp. */
	uint32_t unc_r;
	/*! Offset angle of first arc edge in degrees from North clockwise (eastwards), 0..359.
	 * Angle is coded in increments of 2 degrees. */
	uint16_t ofs_angle;
	/*! Included angle defining the angular width of the arc, in degrees clockwise, 1..360.
	 * Angle is coded in increments of 2 degrees. */
	uint16_t incl_angle;
	/*! Confidence in percent, 0 = no information, 1..100%, 101..128 = no information. */
	uint8_t confidence;
};

struct osmo_gad_ha_ell_point_alt_unc_ell {
	/*! latitude in micro degrees (degrees * 1e6), -90'000'000 (S) .. 90'000'000 (N). */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6), -180'000'000 (W) .. 180'000'000 (E). */
	int32_t lon;
	/*! Altitude in millimeters, -500'000 (depth) .. 10'000'000 (height) */
	int32_t alt;
	/*! Uncertainty ellipsoid radius of major axis in millimeters, 0 .. 46'491.
	 * Coding of high-accuracy uncertainty is non-linear, use osmo_gad_dec_ha_unc(osmo_gad_enc_ha_unc(val)) to
	 * clamp. */
	uint32_t unc_semi_major;
	/*! Uncertainty ellipsoid radius of minor axis in millimeters, 0 .. 46'491.
	 * Coding of high-accuracy uncertainty is non-linear, use osmo_gad_dec_ha_unc(osmo_gad_enc_ha_unc(val)) to
	 * clamp. */
	uint32_t unc_semi_minor;
	/*! Major axis orientation in degrees (DEG), 0 (N) .. 90 (E) .. 179 (SSE). */
	uint8_t major_ori;
	/*! Horizontal confidence in percent, 0 = no information, 1..100%, 101..128 = no information. */
	uint8_t h_confidence;
	/*! High-Accuracy uncertainty altitude */
	int32_t unc_alt;
	/*! Vertical confidence in percent, 0 = no information, 1..100%, 101..128 = no information. */
	uint8_t v_confidence;
};

struct osmo_gad {
	enum gad_type type;
	union {
		struct osmo_gad_ell_point ell_point;
		struct osmo_gad_ell_point_unc_circle ell_point_unc_circle;
		struct osmo_gad_ell_point_unc_ellipse ell_point_unc_ellipse;
		struct osmo_gad_polygon polygon;
		struct osmo_gad_ell_point_alt ell_point_alt;
		struct osmo_gad_ell_point_alt_unc_ell ell_point_alt_unc_ell;
		struct osmo_gad_ell_arc ell_arc;
		struct osmo_gad_ell_point_unc_ellipse ha_ell_point_unc_ellipse;
		struct osmo_gad_ha_ell_point_alt_unc_ell ha_ell_point_alt_unc_ell;
	};
};

struct osmo_gad_err {
	int rc;
	enum gad_type type;
	char *logmsg;
};

extern const struct value_string osmo_gad_type_names[];
static inline const char *osmo_gad_type_name(enum gad_type val)
{ return get_value_string(osmo_gad_type_names, val); }

int osmo_gad_raw_write(struct msgb *msg, const union gad_raw *gad_raw);
int osmo_gad_raw_read(union gad_raw *gad_raw, struct osmo_gad_err **err, void *err_ctx, const uint8_t *data, uint8_t len);

int osmo_gad_enc(union gad_raw *gad_raw, const struct osmo_gad *gad);
int osmo_gad_dec(struct osmo_gad *gad, struct osmo_gad_err **err, void *err_ctx, const union gad_raw *gad_raw);

int osmo_gad_to_str_buf(char *buf, size_t buflen, const struct osmo_gad *gad);
char *osmo_gad_to_str_c(void *ctx, const struct osmo_gad *gad);

uint32_t osmo_gad_enc_lat(int32_t deg_1e6);
int32_t osmo_gad_dec_lat(uint32_t lat);
uint32_t osmo_gad_enc_lon(int32_t deg_1e6);
int32_t osmo_gad_dec_lon(uint32_t lon);
uint8_t osmo_gad_enc_unc(uint32_t mm);
uint32_t osmo_gad_dec_unc(uint8_t unc);
/*! @} */
