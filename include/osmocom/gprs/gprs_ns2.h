/*! \file gprs_ns2.h */


#pragma once

#include <stdint.h>
#include <netinet/in.h>

#include <osmocom/core/prim.h>

struct osmo_sockaddr;
struct osmo_sockaddr_str;

struct gprs_ns2_inst;
struct gprs_ns2_nse;
struct gprs_ns2_vc;
struct gprs_ns2_vc_bind;
struct gprs_ns2_vc_driver;
struct gprs_ns_ie_ip4_elem;
struct gprs_ns_ie_ip6_elem;

enum gprs_ns2_vc_mode {
	NS2_VC_MODE_BLOCKRESET, /* The VC will use RESET/BLOCK/UNBLOCK to start the connection and do ALIVE/ACK */
	NS2_VC_MODE_ALIVE, /* The will only use ALIVE/ACK */
};

/*! Osmocom NS primitives according to 48.016 5.2 Service primitves */
enum gprs_ns2_prim {
	PRIM_NS_UNIT_DATA,
	PRIM_NS_CONGESTION,
	PRIM_NS_STATUS,
};

/*! Osmocom NS primitives according to 48.016 5.2.2.4 Service primitves */
enum gprs_ns2_congestion_cause {
	NS_CONG_CAUSE_BACKWARD_BEGIN,
	NS_CONG_CAUSE_BACKWARD_END,
	NS_CONG_CAUSE_FORWARD_BEGIN,
	NS_CONG_CAUSE_FORWARD_END,
};

/*! Osmocom NS primitives according to 48.016 5.2.2.6 Service primitves */
enum gprs_ns2_affecting_cause {
	NS_AFF_CAUSE_VC_FAILURE,
	NS_AFF_CAUSE_VC_RECOVERY,
	NS_AFF_CAUSE_FAILURE,
	NS_AFF_CAUSE_RECOVERY,
	/* osmocom own causes */
	NS_AFF_CAUSE_SNS_CONFIGURED,
	NS_AFF_CAUSE_SNS_FAILURE,
};

/*! Osmocom NS primitives according to 48.016 5.2.2.7 Service primitves */
enum gprs_ns2_change_ip_endpoint {
	NS_ENDPOINT_NO_CHANGE,
	NS_ENDPOINT_REQUEST_CHANGE,
	NS_ENDPOINT_CONFIRM_CHANGE,
};

struct osmo_gprs_ns2_prim {
	struct osmo_prim_hdr oph;

	uint16_t nsei;
	uint16_t bvci;

	union {
		struct {
			enum gprs_ns2_change_ip_endpoint change;
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
			/* 48.016 5.2.2.6 transfer capability */
			int transfer;
			/* osmocom specific */
			/* Persistent NSE/NSVC are configured by vty */
			bool persistent;
			/* Only true on the first time it's available.
			 * Allow the BSSGP layer to reset persistent NSE */
			bool first;
		} status;
	} u;
};

/* instance */
struct gprs_ns2_inst *gprs_ns2_instantiate(void *ctx, osmo_prim_cb cb, void *cb_data);
void gprs_ns2_free(struct gprs_ns2_inst *inst);
int gprs_ns2_dynamic_create_nse(struct gprs_ns2_inst *nsi, bool create_nse);

/* Entrypoint for primitives from the NS USER */
int gprs_ns2_recv_prim(struct gprs_ns2_inst *nsi, struct osmo_prim_hdr *oph);

struct gprs_ns2_nse *gprs_ns2_nse_by_nsei(struct gprs_ns2_inst *nsi, uint16_t nsei);
struct gprs_ns2_nse *gprs_ns2_create_nse(struct gprs_ns2_inst *nsi, uint16_t nsei);
uint16_t gprs_ns2_nse_nsei(struct gprs_ns2_nse *nse);
void gprs_ns2_free_nse(struct gprs_ns2_nse *nse);
void gprs_ns2_free_nses(struct gprs_ns2_inst *nsi);

/* create vc */
void gprs_ns2_free_nsvc(struct gprs_ns2_vc *nsvc);
struct gprs_ns2_vc *gprs_ns2_nsvc_by_nsvci(struct gprs_ns2_inst *nsi, uint16_t nsvci);

/* IP VL driver */
int gprs_ns2_ip_bind(struct gprs_ns2_inst *nsi,
		     const struct osmo_sockaddr *local,
		     int dscp,
		     struct gprs_ns2_vc_bind **result);
struct gprs_ns2_vc_bind *gprs_ns2_ip_bind_by_sockaddr(struct gprs_ns2_inst *nsi,
						      const struct osmo_sockaddr *sockaddr);
void gprs_ns2_bind_set_mode(struct gprs_ns2_vc_bind *bind, enum gprs_ns2_vc_mode mode);

/* create a VC connection */
struct gprs_ns2_vc *gprs_ns2_ip_connect(struct gprs_ns2_vc_bind *bind,
					const struct osmo_sockaddr *remote,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci);

struct gprs_ns2_vc *gprs_ns2_ip_connect2(struct gprs_ns2_vc_bind *bind,
					 const struct osmo_sockaddr *remote,
					 uint16_t nsei,
					 uint16_t nsvci);
struct gprs_ns2_vc *gprs_ns2_ip_connect_inactive(struct gprs_ns2_vc_bind *bind,
					const struct osmo_sockaddr *remote,
					struct gprs_ns2_nse *nse,
					uint16_t nsvci);

void gprs_ns2_free_bind(struct gprs_ns2_vc_bind *bind);
void gprs_ns2_free_binds(struct gprs_ns2_inst *nsi);

/* create a VC SNS connection */
int gprs_ns2_ip_connect_sns(struct gprs_ns2_vc_bind *bind,
			    const struct osmo_sockaddr *remote,
			    uint16_t nsei);

const struct osmo_sockaddr *gprs_ns2_ip_vc_remote(struct gprs_ns2_vc *nsvc);
const struct osmo_sockaddr *gprs_ns2_ip_vc_local(const struct gprs_ns2_vc *nsvc);
const struct osmo_sockaddr *gprs_ns2_ip_bind_sockaddr(struct gprs_ns2_vc_bind *bind);
int gprs_ns2_is_ip_bind(struct gprs_ns2_vc_bind *bind);
int gprs_ns2_ip_bind_set_dscp(struct gprs_ns2_vc_bind *bind, int dscp);
struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_bind(
		struct gprs_ns2_vc_bind *bind,
		const struct osmo_sockaddr *saddr);

int gprs_ns2_frgre_bind(struct gprs_ns2_inst *nsi,
			const struct osmo_sockaddr *local,
			int dscp,
			struct gprs_ns2_vc_bind **result);
int gprs_ns2_is_frgre_bind(struct gprs_ns2_vc_bind *bind);

struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_nse(
		struct gprs_ns2_nse *nse,
		const struct osmo_sockaddr *sockaddr);
void gprs_ns2_start_alive_all_nsvcs(struct gprs_ns2_nse *nse);
const char *gprs_ns2_cause_str(int cause);
const char *gprs_ns2_ll_str(struct gprs_ns2_vc *nsvc);
char *gprs_ns2_ll_str_buf(char *buf, size_t buf_len, struct gprs_ns2_vc *nsvc);
char *gprs_ns2_ll_str_c(const void *ctx, struct gprs_ns2_vc *nsvc);

/* vty */
int gprs_ns2_vty_init(struct gprs_ns2_inst *nsi,
		      const struct osmo_sockaddr_str *default_bind);
int gprs_ns2_vty_create();
void gprs_ns2_vty_force_vc_mode(bool force, enum gprs_ns2_vc_mode mode, const char *reason);


/*! @} */
