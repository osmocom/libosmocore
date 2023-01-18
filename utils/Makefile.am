
bin_PROGRAMS =
noinst_PROGRAMS =
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -Wall $(TALLOC_CFLAGS) $(PTHREAD_CFLAGS)
LDADD = $(top_builddir)/src/core/libosmocore.la $(top_builddir)/src/gsm/libosmogsm.la $(PTHREAD_LIBS)

if ENABLE_UTILITIES
EXTRA_DIST = conv_gen.py conv_codes_gsm.py

bin_PROGRAMS += osmo-arfcn osmo-auc-gen osmo-config-merge osmo-aka-verify

osmo_arfcn_SOURCES = osmo-arfcn.c

osmo_auc_gen_SOURCES = osmo-auc-gen.c

osmo_aka_verify_SOURCES = osmo-aka-verify.c

osmo_config_merge_SOURCES = osmo-config-merge.c
osmo_config_merge_LDADD = $(LDADD) $(TALLOC_LIBS)
osmo_config_merge_CFLAGS = $(TALLOC_CFLAGS)

if ENABLE_PCSC
noinst_PROGRAMS += osmo-sim-test
osmo_sim_test_SOURCES = osmo-sim-test.c
osmo_sim_test_LDADD = $(LDADD) $(top_builddir)/src/sim/libosmosim.la $(PCSC_LIBS)
osmo_sim_test_CFLAGS = $(PCSC_CFLAGS)
endif
endif

if ENABLE_EXT_TESTS
SUBDIRS = \
	osmo-stat-dummy \
	$(NULL)

if ENABLE_GB
noinst_PROGRAMS += osmo-ns-dummy
osmo_ns_dummy_SOURCES = osmo-ns-dummy.c osmo-ns-dummy-vty.c
osmo_ns_dummy_LDADD = $(LDADD) $(TALLOC_LIBS) \
			$(top_builddir)/src/gb/libosmogb.la \
			$(top_builddir)/src/vty/libosmovty.la \
			$(top_builddir)/src/ctrl/libosmoctrl.la \
			$(top_builddir)/src/gsm/libosmogsm.la
osmo_ns_dummy_CFLAGS = $(TALLOC_CFLAGS)
endif
endif
