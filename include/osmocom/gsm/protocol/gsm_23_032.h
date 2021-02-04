/*! \defgroup gad 3GPP TS 23.032 GAD: Universal Geographical Area Description.
 *  @{
 *  \file gsm_23_032.h
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

#include <stdint.h>
#include <osmocom/core/endian.h>

enum gad_type {
	/*! Ellipsoid point */
	GAD_TYPE_ELL_POINT = 0,
	/*! Ellipsoid point with uncertainty circle. */
	GAD_TYPE_ELL_POINT_UNC_CIRCLE = 1,
	/*! Ellipsoid point with uncertainty ellipse. */
	GAD_TYPE_ELL_POINT_UNC_ELLIPSE = 3,
	GAD_TYPE_POLYGON = 5,
	/*! Ellipsoid point with altitude. */
	GAD_TYPE_ELL_POINT_ALT = 8,
	/*! Ellipsoid point with altitude and uncertainty ellipsoid. */
	GAD_TYPE_ELL_POINT_ALT_UNC_ELL = 9,
	/*! Ellipsoid arc */
	GAD_TYPE_ELL_ARC = 10,
	/*! High accuracy ellipsoid point with uncertainty ellipse. */
	GAD_TYPE_HA_ELL_POINT_UNC_ELLIPSE = 11,
	/*! High accuracy ellipsoid point with altitude and uncertainty ellipsoid. */
	GAD_TYPE_HA_ELL_POINT_ALT_UNC_ELL = 12,
};

struct gad_raw_head {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t spare:4,
		type:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t type:4, spare:4;
#endif
} __attribute__ ((packed));

struct gad_raw_ell_point {
	struct gad_raw_head h; /*!< type = GAD_TYPE_ELL_POINT */
	uint8_t lat[3];
	uint8_t lon[3];
} __attribute__ ((packed));

struct gad_raw_ell_point_unc_circle {
#if OSMO_IS_LITTLE_ENDIAN
	struct gad_raw_head h; /*!< type = GAD_TYPE_ELL_POINT_UNC_CIRCLE */
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t unc:7,
		spare2:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct gad_raw_head h;
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t spare2:1, unc:7;
#endif
} __attribute__ ((packed));

struct gad_raw_ell_point_unc_ellipse {
#if OSMO_IS_LITTLE_ENDIAN
	struct gad_raw_head h; /*!< type = GAD_TYPE_ELL_POINT_UNC_ELLIPSE */
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t unc_semi_major:7,
		spare1:1;
	uint8_t unc_semi_minor:7,
		spare2:1;
	uint8_t major_ori;
	uint8_t confidence:7,
		spare3:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct gad_raw_head h;
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t spare1:1, unc_semi_major:7;
	uint8_t spare2:1, unc_semi_minor:7;
	uint8_t major_ori;
	uint8_t spare3:1, confidence:7;
#endif
} __attribute__ ((packed));

struct gad_raw_polygon {
	struct {
#if OSMO_IS_LITTLE_ENDIAN
		uint8_t num_points:4;
		uint8_t type:4; /*!< type = GAD_TYPE_POLYGON */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
		uint8_t type:4, num_points:4;
#endif
	} h;
	struct {
		uint8_t lat[3];
		uint8_t lon[3];
	} point[15];
} __attribute__ ((packed));

struct gad_raw_ell_point_alt {
	struct gad_raw_head h; /*!< type = GAD_TYPE_ELL_POINT_ALT */
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t alt[2];
} __attribute__ ((packed));

struct gad_raw_ell_point_alt_unc_ell {
#if OSMO_IS_LITTLE_ENDIAN
	struct gad_raw_head h; /*!< type = GAD_TYPE_ELL_POINT_ALT_UNC_ELL */
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t alt[2];
	uint8_t unc_semi_major:7,
		spare1:1;
	uint8_t unc_semi_minor:7,
		spare2:1;
	uint8_t major_ori;
	uint8_t unc_alt:7,
		spare3:1;
	uint8_t confidence:7,
		spare4:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct gad_raw_head h;
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t alt[2];
	uint8_t spare1:1, unc_semi_major:7;
	uint8_t spare2:1, unc_semi_minor:7;
	uint8_t major_ori;
	uint8_t spare3:1, unc_alt:7;
	uint8_t spare4:1, confidence:7;
#endif
} __attribute__ ((packed));

struct gad_raw_ell_arc {
#if OSMO_IS_LITTLE_ENDIAN
	struct gad_raw_head h; /*!< type = GAD_TYPE_ELL_ARC */
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t inner_r[2];
	uint8_t unc_r:7,
		spare1:1;
	uint8_t ofs_angle;
	uint8_t incl_angle;
	uint8_t confidence:7,
		spare2:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct gad_raw_head h;
	uint8_t lat[3];
	uint8_t lon[3];
	uint8_t inner_r[2];
	uint8_t spare1:1, unc_r:7;
	uint8_t ofs_angle;
	uint8_t incl_angle;
	uint8_t spare2:1, confidence:7;
#endif
} __attribute__ ((packed));

struct gad_raw_ha_ell_point_unc_ell {
#if OSMO_IS_LITTLE_ENDIAN
	struct gad_raw_head h; /*!< type = GAD_TYPE_HA_ELL_POINT_UNC_ELLIPSE */
	uint8_t lat[4];
	uint8_t lon[4];
	uint8_t alt[3];
	uint8_t unc_semi_major;
	uint8_t unc_semi_minor;
	uint8_t major_ori;
	uint8_t confidence:7,
		spare1:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct gad_raw_head h;
	uint8_t lat[4];
	uint8_t lon[4];
	uint8_t alt[3];
	uint8_t unc_semi_major;
	uint8_t unc_semi_minor;
	uint8_t major_ori;
	uint8_t spare1:1, confidence:7;
#endif
} __attribute__ ((packed));

struct gad_raw_ha_ell_point_alt_unc_ell {
#if OSMO_IS_LITTLE_ENDIAN
	struct gad_raw_head h; /*!< type = GAD_TYPE_HA_ELL_POINT_ALT_UNC_ELL */
	uint8_t lat[4];
	uint8_t lon[4];
	uint8_t alt[3];
	uint8_t unc_semi_major;
	uint8_t unc_semi_minor;
	uint8_t major_ori;
	uint8_t h_confidence:7,
		spare1:1;
	uint8_t unc_alt;
	uint8_t v_confidence:7,
		spare2:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct gad_raw_head h;
	uint8_t lat[4];
	uint8_t lon[4];
	uint8_t alt[3];
	uint8_t unc_semi_major;
	uint8_t unc_semi_minor;
	uint8_t major_ori;
	uint8_t spare1:1, h_confidence:7;
	uint8_t unc_alt;
	uint8_t spare2:1, v_confidence:7;
#endif
} __attribute__ ((packed));

/*! GAD PDU in network-byte-order according to 3GPP TS 23.032 GAD: Universal Geographical Area Description. */
union gad_raw {
	struct gad_raw_head h;
	struct gad_raw_ell_point ell_point;
	struct gad_raw_ell_point_unc_circle ell_point_unc_circle;
	struct gad_raw_ell_point_unc_ellipse ell_point_unc_ellipse;
	struct gad_raw_polygon polygon;
	struct gad_raw_ell_point_alt ell_point_alt;
	struct gad_raw_ell_point_alt_unc_ell ell_point_alt_unc_ell;
	struct gad_raw_ell_arc ell_arc;
	struct gad_raw_ha_ell_point_unc_ell ha_ell_point_unc_ell;
	struct gad_raw_ha_ell_point_alt_unc_ell ha_ell_point_alt_unc_ell;
} __attribute__ ((packed));

/*! @} */
