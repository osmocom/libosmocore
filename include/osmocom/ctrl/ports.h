/*! \file ports.h
 * TCP port numbers used for CTRL interfaces in osmocom projects. See also the
 * osmocom wiki as well as the osmo-gsm-manuals, which should all be kept in
 * sync with this file:
 * https://osmocom.org/projects/cellular-infrastructure/wiki/PortNumbers
 * https://git.osmocom.org/osmo-gsm-manuals/tree/common/chapters/port_numbers.adoc
 */

#pragma once


#define OSMO_CTRL_PORT_TRX	4236
/* 4237 used by VTY interface */
#define OSMO_CTRL_PORT_BTS	4238
#define OSMO_CTRL_PORT_NITB_BSC	4249
#define OSMO_CTRL_PORT_BSC_NAT	4250
#define OSMO_CTRL_PORT_SGSN	4251
/* 4252-4254 used by VTY interface */
#define OSMO_CTRL_PORT_MSC	4255
/* 4256 used by VTY interface */
#define OSMO_CTRL_PORT_GGSN	4257
#define OSMO_CTRL_PORT_HLR	4259
#define OSMO_CTRL_PORT_HNBGW	4262
#define OSMO_CTRL_PORT_GBPROXY	4263
/* 4264 used by VTY interface */
#define OSMO_CTRL_PORT_CBC	4265
/* When adding/changing port numbers, keep docs and wiki in sync. See above. */
