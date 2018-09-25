if ENABLE_UTILITIES
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include $(TALLOC_CFLAGS)
AM_CFLAGS = -Wall
LDADD = $(top_builddir)/src/libosmocore.la $(top_builddir)/src/gsm/libosmogsm.la

EXTRA_DIST = conv_gen.py conv_codes_gsm.py

bin_PROGRAMS = osmo-arfcn osmo-auc-gen osmo-config-merge

osmo_arfcn_SOURCES = osmo-arfcn.c

osmo_auc_gen_SOURCES = osmo-auc-gen.c

osmo_config_merge_SOURCES = osmo-config-merge.c
osmo_config_merge_LDADD = $(LDADD) $(TALLOC_LIBS)
osmo_config_merge_CFLAGS = $(TALLOC_CFLAGS)

if ENABLE_PCSC
noinst_PROGRAMS = osmo-sim-test
osmo_sim_test_SOURCES = osmo-sim-test.c
osmo_sim_test_LDADD = $(LDADD) $(top_builddir)/src/sim/libosmosim.la $(PCSC_LIBS)
osmo_sim_test_CFLAGS = $(PCSC_CFLAGS)
endif
endif
