#pragma once

/*! \defgroup prim Osmocom primitives
 *  @{
 * \file prim.h */

#include <stdint.h>
#include <osmocom/core/msgb.h>

#define OSMO_PRIM(prim, op)	((prim << 8) | (op & 0xFF))
#define OSMO_PRIM_HDR(oph)	OSMO_PRIM((oph)->primitive, (oph)->operation)

/*! primitive operation */
enum osmo_prim_operation {
	PRIM_OP_REQUEST,	/*!< request */
	PRIM_OP_RESPONSE,	/*!< response */
	PRIM_OP_INDICATION,	/*!< indication */
	PRIM_OP_CONFIRM,	/*!< confirm */
};

extern const struct value_string osmo_prim_op_names[5];

#define _SAP_GSM_SHIFT	24

#define _SAP_GSM_BASE	(0x01 << _SAP_GSM_SHIFT)
#define _SAP_TETRA_BASE	(0x02 << _SAP_GSM_SHIFT)
#define _SAP_SS7_BASE	(0x03 << _SAP_GSM_SHIFT)

/*! primitive header */
struct osmo_prim_hdr {
	unsigned int sap;	/*!< Service Access Point */
	unsigned int primitive;	/*!< Primitive number */
	enum osmo_prim_operation operation; /*! Primitive Operation */
	struct msgb *msg;	/*!< \ref msgb containing associated data */
};

/*! initialize a primitive header
 *  \param[in,out] oph primitive header
 *  \param[in] sap Service Access Point
 *  \param[in] primitive Primitive Number
 *  \param[in] operation Primitive Operation (REQ/RESP/IND/CONF)
 *  \param[in] msg Message
 */
static inline void
osmo_prim_init(struct osmo_prim_hdr *oph, unsigned int sap,
		unsigned int primitive, enum osmo_prim_operation operation,
		struct msgb *msg)
{
	oph->sap = sap;
	oph->primitive = primitive;
	oph->operation = operation;
	oph->msg = msg;
}

/*! primitive handler callback type */
typedef int (*osmo_prim_cb)(struct osmo_prim_hdr *oph, void *ctx);

/*! magic value to be used as final record of \ref
 * osmo_prim_event_map */
#define OSMO_NO_EVENT	0xFFFFFFFF

/*! single entry in a SAP/PRIM/OP -> EVENT map */
struct osmo_prim_event_map {
	unsigned int sap;	/*!< SAP to match */
	unsigned int primitive;	/*!< primtiive to match */
	enum osmo_prim_operation operation; /*!< operation to match */
	uint32_t event;		/*!< event as result if above match */
};

uint32_t osmo_event_for_prim(const struct osmo_prim_hdr *oph,
			     const struct osmo_prim_event_map *maps);
/*! @} */
