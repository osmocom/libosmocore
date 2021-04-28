/*! \file gprs_ns2.h */


#pragma once

#include <stdint.h>
#include <netinet/in.h>

#include <osmocom/core/prim.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>
#include <osmocom/gprs/frame_relay.h>

struct osmo_sockaddr;
struct osmo_sockaddr_str;
struct osmo_fr_network;

struct gprs_ns2_inst;
struct gprs_ns2_nse;
struct gprs_ns2_vc;
struct gprs_ns2_vc_bind;
struct gprs_ns2_vc_driver;
struct gprs_ns_ie_ip4_elem;
struct gprs_ns_ie_ip6_elem;

enum gprs_ns2_vc_mode {
	/*! The VC will use RESET/BLOCK/UNBLOCK to start the connection and do ALIVE/ACK.
	 * This is what is needed for Frame Relay transport, and if you use a R97/R99 Gb
	 * interface over an IP transport (never standardized by 3GPP) */
	GPRS_NS2_VC_MODE_BLOCKRESET,
	/*! The VC will only use ALIVE/ACK (no RESET/BLOCK/UNBLOCK), which is for Gb-IP
	 * interface compliant to 3GPP Rel=4 or later. */
	GPRS_NS2_VC_MODE_ALIVE,
};

enum gprs_ns2_dialect {
	GPRS_NS2_DIALECT_UNDEF,
	GPRS_NS2_DIALECT_STATIC_ALIVE,
	GPRS_NS2_DIALECT_STATIC_RESETBLOCK,
	GPRS_NS2_DIALECT_IPACCESS,
	GPRS_NS2_DIALECT_SNS,
};

/*! Osmocom NS link layer types */
enum gprs_ns2_ll {
	GPRS_NS2_LL_UNDEF,	/*!< undefined, used by vty */
	GPRS_NS2_LL_UDP,	/*!< NS/UDP/IP */
	GPRS_NS2_LL_FR,		/*!< NS/FR */
	GPRS_NS2_LL_FR_GRE,	/*!< NS/FR/GRE/IP */
};

/*! Osmocom NS primitives according to 48.016 5.2 Service primitives */
enum gprs_ns2_prim {
	GPRS_NS2_PRIM_UNIT_DATA,
	GPRS_NS2_PRIM_CONGESTION,
	GPRS_NS2_PRIM_STATUS,
};

extern const struct value_string gprs_ns2_prim_strs[];
extern const struct value_string gprs_ns2_lltype_strs[];

/*! Obtain a human-readable string for NS primitives */
static inline const char *gprs_ns2_prim_str(enum gprs_ns2_prim val)
{ return get_value_string(gprs_ns2_prim_strs, val); }

/*! Obtain a human-readable string for NS link-layer type */
static inline const char *gprs_ns2_lltype_str(enum gprs_ns2_ll val)
{ return get_value_string(gprs_ns2_lltype_strs, val); }

/*! Osmocom NS primitives according to 48.016 5.2.2.4 Service primitives */
enum gprs_ns2_congestion_cause {
	GPRS_NS2_CONG_CAUSE_BACKWARD_BEGIN,
	GPRS_NS2_CONG_CAUSE_BACKWARD_END,
	GPRS_NS2_CONG_CAUSE_FORWARD_BEGIN,
	GPRS_NS2_CONG_CAUSE_FORWARD_END,
};

/*! Osmocom NS primitives according to 48.016 5.2.2.6 Service primitives */
enum gprs_ns2_affecting_cause {
	GPRS_NS2_AFF_CAUSE_VC_FAILURE,
	GPRS_NS2_AFF_CAUSE_VC_RECOVERY,
	GPRS_NS2_AFF_CAUSE_FAILURE,
	GPRS_NS2_AFF_CAUSE_RECOVERY,
	/* osmocom own causes */
	GPRS_NS2_AFF_CAUSE_SNS_CONFIGURED,
	GPRS_NS2_AFF_CAUSE_SNS_FAILURE,
	GPRS_NS2_AFF_CAUSE_SNS_NO_ENDPOINTS,
	GPRS_NS2_AFF_CAUSE_MTU_CHANGE,
};

extern const struct value_string gprs_ns2_aff_cause_prim_strs[];

/*! Obtain a human-readable string for NS affecting cause in primitives */
static inline const char *gprs_ns2_aff_cause_prim_str(enum gprs_ns2_affecting_cause val)
{ return get_value_string(gprs_ns2_aff_cause_prim_strs, val); }

/*! Osmocom NS primitives according to 48.016 5.2.2.7 Service primitives */
enum gprs_ns2_change_ip_endpoint {
	GRPS_NS2_ENDPOINT_NO_CHANGE,
	GPRS_NS2_ENDPOINT_REQUEST_CHANGE,
	GPRS_NS2_ENDPOINT_CONFIRM_CHANGE,
};

extern const struct value_string gprs_ns2_cause_strs[];

/*! Obtain a human-readable string for NS primitives */
static inline const char *gprs_ns2_cause_str(enum ns_cause val)
{ return get_value_string(gprs_ns2_cause_strs, val); }

struct osmo_gprs_ns2_prim {
	struct osmo_prim_hdr oph;

	uint16_t nsei;
	uint16_t bvci;

	union {
		struct {
			enum gprs_ns2_change_ip_endpoint change;
			uint32_t link_selector;
			/* TODO: implement resource distribution
			 * add place holder for the link selector */
			long long _resource_distribution_placeholder1;
			long long _resource_distribution_placeholder2;
			long long _resource_distribution_placeholder3;
		} unitdata;
		struct {
			enum gprs_ns2_congestion_cause cause;
		} congestion;
		struct {
			enum gprs_ns2_affecting_cause cause;
			char *nsvc;
			/* 48.016 5.2.2.6 transfer capability */
			int transfer;
			/* osmocom specific */
			/* Persistent NSE/NSVC are configured by vty */
			bool persistent;
			/* Only true on the first time it's available.
			 * Allow the BSSGP layer to reset persistent NSE */
			bool first;
			/* MTU of a NS SDU. It's the lowest MTU of all (alive & dead) NSVCs */
			uint16_t mtu;
		} status;
	} u;
};

/* instance */
struct gprs_ns2_inst *gprs_ns2_instantiate(void *ctx, osmo_prim_cb cb, void *cb_data);
void gprs_ns2_free(struct gprs_ns2_inst *inst);

/* Entrypoint for primitives from the NS USER */
int gprs_ns2_recv_prim(struct gprs_ns2_inst *nsi, struct osmo_prim_hdr *oph);

/*! a callback to iterate over all NSVC */
typedef int (*gprs_ns2_foreach_nsvc_cb)(struct gprs_ns2_vc *nsvc, void *ctx);

int gprs_ns2_nse_foreach_nsvc(struct gprs_ns2_nse *nse,
			      gprs_ns2_foreach_nsvc_cb cb, void *cb_data);
struct gprs_ns2_nse *gprs_ns2_nse_by_nsei(struct gprs_ns2_inst *nsi, uint16_t nsei);
struct gprs_ns2_nse *gprs_ns2_create_nse(struct gprs_ns2_inst *nsi, uint16_t nsei,
					 enum gprs_ns2_ll linklayer,
					 enum gprs_ns2_dialect dialect);
struct gprs_ns2_nse *gprs_ns2_create_nse2(struct gprs_ns2_inst *nsi, uint16_t nsei,
					 enum gprs_ns2_ll linklayer,
					 enum gprs_ns2_dialect dialect, bool local_sgsn_role);
uint16_t gprs_ns2_nse_nsei(struct gprs_ns2_nse *nse);
void gprs_ns2_free_nse(struct gprs_ns2_nse *nse);
void gprs_ns2_free_nses(struct gprs_ns2_inst *nsi);

/* create vc */
void gprs_ns2_free_nsvc(struct gprs_ns2_vc *nsvc);
void gprs_ns2_free_nsvcs(struct gprs_ns2_nse *nse);
struct gprs_ns2_vc *gprs_ns2_nsvc_by_nsvci(struct gprs_ns2_inst *nsi, uint16_t nsvci);

/* generic VL driver */
struct gprs_ns2_vc_bind *gprs_ns2_bind_by_name(struct gprs_ns2_inst *nsi,
					       const char *name);

/* IP VL driver */
int gprs_ns2_ip_bind(struct gprs_ns2_inst *nsi,
		     const char *name,
		     const struct osmo_sockaddr *local,
		     int dscp,
		     struct gprs_ns2_vc_bind **result);
struct gprs_ns2_vc_bind *gprs_ns2_ip_bind_by_sockaddr(struct gprs_ns2_inst *nsi,
						      const struct osmo_sockaddr *sockaddr);

/* FR VL driver */
struct gprs_ns2_vc_bind *gprs_ns2_fr_bind_by_netif(
		struct gprs_ns2_inst *nsi,
		const char *netif);
const char *gprs_ns2_fr_bind_netif(struct gprs_ns2_vc_bind *bind);
enum osmo_fr_role gprs_ns2_fr_bind_role(struct gprs_ns2_vc_bind *bind);
int gprs_ns2_fr_bind(struct gprs_ns2_inst *nsi,
		     const char *name,
		     const char *netif,
		     struct osmo_fr_network *fr_network,
		     enum osmo_fr_role fr_role,
		     struct gprs_ns2_vc_bind **result);
int gprs_ns2_is_fr_bind(struct gprs_ns2_vc_bind *bind);
struct gprs_ns2_vc *gprs_ns2_fr_nsvc_by_dlci(struct gprs_ns2_vc_bind *bind, uint16_t dlci);
struct gprs_ns2_vc *gprs_ns2_fr_connect(struct gprs_ns2_vc_bind *bind,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci,
					uint16_t dlci);
struct gprs_ns2_vc *gprs_ns2_fr_connect2(struct gprs_ns2_vc_bind *bind,
					uint16_t nsei,
					uint16_t nsvci,
					uint16_t dlci);

/* create a VC connection */
struct gprs_ns2_vc *gprs_ns2_ip_connect(struct gprs_ns2_vc_bind *bind,
					const struct osmo_sockaddr *remote,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci);

struct gprs_ns2_vc *gprs_ns2_ip_connect2(struct gprs_ns2_vc_bind *bind,
					 const struct osmo_sockaddr *remote,
					 uint16_t nsei,
					 uint16_t nsvci,
					 enum gprs_ns2_dialect dialect);
struct gprs_ns2_vc *gprs_ns2_ip_connect_inactive(struct gprs_ns2_vc_bind *bind,
					const struct osmo_sockaddr *remote,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci);
void gprs_ns2_ip_bind_set_sns_weight(struct gprs_ns2_vc_bind *bind,
				     uint8_t signalling, uint8_t data);

void gprs_ns2_free_bind(struct gprs_ns2_vc_bind *bind);
void gprs_ns2_free_binds(struct gprs_ns2_inst *nsi);

/* create a VC SNS connection */
int gprs_ns2_sns_count(struct gprs_ns2_nse *nse);
int gprs_ns2_sns_add_endpoint(struct gprs_ns2_nse *nse,
				   const struct osmo_sockaddr *saddr);
int gprs_ns2_sns_del_endpoint(struct gprs_ns2_nse *nse,
				   const struct osmo_sockaddr *saddr);
int gprs_ns2_sns_add_bind(struct gprs_ns2_nse *nse, struct gprs_ns2_vc_bind *bind);
int gprs_ns2_sns_del_bind(struct gprs_ns2_nse *nse, struct gprs_ns2_vc_bind *bind);
const struct osmo_sockaddr *gprs_ns2_nse_sns_remote(struct gprs_ns2_nse *nse);

const struct osmo_sockaddr *gprs_ns2_ip_vc_remote(const struct gprs_ns2_vc *nsvc);
const struct osmo_sockaddr *gprs_ns2_ip_vc_local(const struct gprs_ns2_vc *nsvc);
bool gprs_ns2_ip_vc_equal(const struct gprs_ns2_vc *nsvc,
			  const struct osmo_sockaddr *local,
			  const struct osmo_sockaddr *remote,
			  uint16_t nsvci);
const struct osmo_sockaddr *gprs_ns2_ip_bind_sockaddr(struct gprs_ns2_vc_bind *bind);
int gprs_ns2_is_ip_bind(struct gprs_ns2_vc_bind *bind);
int gprs_ns2_ip_bind_set_dscp(struct gprs_ns2_vc_bind *bind, int dscp);
int gprs_ns2_ip_bind_set_priority(struct gprs_ns2_vc_bind *bind, uint8_t priority);
struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_bind(
		struct gprs_ns2_vc_bind *bind,
		const struct osmo_sockaddr *saddr);

int gprs_ns2_frgre_bind(struct gprs_ns2_inst *nsi,
			const char *name,
			const struct osmo_sockaddr *local,
			int dscp,
			struct gprs_ns2_vc_bind **result);
int gprs_ns2_is_frgre_bind(struct gprs_ns2_vc_bind *bind);
uint16_t gprs_ns2_fr_nsvc_dlci(const struct gprs_ns2_vc *nsvc);

struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_nse(
		struct gprs_ns2_nse *nse,
		const struct osmo_sockaddr *sockaddr);
void gprs_ns2_start_alive_all_nsvcs(struct gprs_ns2_nse *nse);

/* VC information */
const char *gprs_ns2_ll_str(struct gprs_ns2_vc *nsvc);
char *gprs_ns2_ll_str_buf(char *buf, size_t buf_len, struct gprs_ns2_vc *nsvc);
char *gprs_ns2_ll_str_c(const void *ctx, struct gprs_ns2_vc *nsvc);
const char *gprs_ns2_nsvc_state_name(struct gprs_ns2_vc *nsvc);

/* vty */
int gprs_ns2_vty_init(struct gprs_ns2_inst *nsi);

/*! @} */
