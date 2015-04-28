#include <string.h>
#include <ares.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

ares_channel osmo_ares_channel;

struct value_string ares_status_strs[25] = {
	/* Server error codes */
	{ ARES_SUCCESS,		"Success" },
	{ ARES_ENODATA,		"Server: No relevant answer" },
	{ ARES_ESERVFAIL,	"Server: Server failure" },
	{ ARES_ENOTFOUND,	"Server: Not found" },
	{ ARES_ENOTIMP,		"Server: Not implemented" },
	{ ARES_EREFUSED,	"Server: Refused" },
	/* Locally generated error codes */
	{ ARES_EBADQUERY,	"Local: Bad Query" },
	{ ARES_EBADNAME,	"Local: Bad Name" },
	{ ARES_EBADFAMILY,	"Local: Bad Family" },
	{ ARES_EBADRESP,	"Local: Bad Response" },
	{ ARES_ECONNREFUSED,	"Local: Connection refused" },
	{ ARES_ETIMEOUT,	"Local: Timeout" },
	{ ARES_EOF,		"Local: End of file" },
	{ ARES_EFILE,		"Local: EFILE?" },
	{ ARES_ENOMEM,		"Local: Out of memory" },
	{ ARES_EDESTRUCTION,	"Local: Destruction?" },
	{ ARES_EBADSTR,		"Local: Bad String?" },
	{ ARES_EBADFLAGS,	"genameinfo: Bad flags" },
	{ ARES_ENONAME,		"getaddrinfo: No name" },
	{ ARES_EBADHINTS,	"getaddrinfo: Bad Hints" },
	{ ARES_ENOTINITIALIZED,	"Library not initialized" },
	{ ARES_ELOADIPHLPAPI,	"?" },
	{ ARES_EADDRGETNETWORKPARAMS, "?" },
	{ ARES_ECANCELLED,	"Cancelled" },
	{ 0, NULL }
};

int osmo_ares_init()
{
	struct ares_options options;
	unsigned int optmask = 0;
	int rc;

	memset(&options, 0, sizeof(options));

	rc = ares_library_init(ARES_LIB_INIT_ALL);
	if (rc != ARES_SUCCESS) {
		LOGP(DLGLOBAL, LOGL_ERROR, "ares_library_init(): %s\n",
		     ares_strerror(rc));
		return -1;
	}

	rc = ares_init_options(&osmo_ares_channel, &options, optmask);
	if (rc != ARES_SUCCESS) {
		LOGP(DLGLOBAL, LOGL_ERROR, "ares_init_options(): %s\n",
		     ares_strerror(rc));
		return -1;
	}

	return 0;
}
