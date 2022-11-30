
bin_PROGRAMS =
noinst_PROGRAMS =
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -Wall $(TALLOC_CFLAGS) $(PTHREAD_CFLAGS)
LDADD = $(top_builddir)/src/core/libosmocore.la $(top_builddir)/src/gsm/libosmogsm.la $(PTHREAD_LIBS)

if ENABLE_UTILITIES
EXTRA_DIST = conv_gen.py conv_codes_gsm.py

bin_PROGRAMS += osmo-arfcn osmo-auc-gen osmo-config-merge osmo-aka-verify osmo-gsmtap-logsend

osmo_arfcn_SOURCES = osmo-arfcn.c

osmo_auc_gen_SOURCES = osmo-auc-gen.c

osmo_aka_verify_SOURCES = osmo-aka-verify.c

osmo_gsmtap_logsend_SOURCES = gsmtap-logsend.c

osmo_config_merge_SOURCES = osmo-config-merge.c
osmo_config_merge_LDADD = $(LDADD) $(TALLOC_LIBS)

if ENABLE_PCSC
noinst_PROGRAMS += osmo-sim-test
osmo_sim_test_SOURCES = osmo-sim-test.c
osmo_sim_test_LDADD = $(LDADD) $(top_builddir)/src/sim/libosmosim.la $(PCSC_LIBS)
osmo_sim_test_CFLAGS = $(AM_CFLAGS) $(PCSC_CFLAGS)
endif
endif

if ENABLE_EXT_TESTS
SUBDIRS = \
	osmo-stat-dummy \
	$(NULL)
endif

if ENABLE_GB
noinst_PROGRAMS += osmo-ns-dummy
osmo_ns_dummy_SOURCES = osmo-ns-dummy.c osmo-ns-dummy-vty.c
osmo_ns_dummy_LDADD = $(LDADD) $(TALLOC_LIBS) \
			$(top_builddir)/src/gb/libosmogb.la \
			$(top_builddir)/src/vty/libosmovty.la \
			$(top_builddir)/src/ctrl/libosmoctrl.la \
			$(NULL)
endif

v110_decode_SOURCES = v110_decode.c
v110_decode_LDADD = $(LDADD) $(top_builddir)/src/isdn/libosmoisdn.la -losmotrau # HACK!
noinst_PROGRAMS += v110_decode

hdlc_decode_SOURCES = hdlc_decode.c
hdlc_decode_LDADD = $(LDADD) #$(top_builddir)/src/isdn/libosmoisdn.la -losmotrau # HACK!
noinst_PROGRAMS += hdlc_decode
