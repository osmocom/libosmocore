if ENABLE_UTILITIES
noinst_PROGRAMS = osmo-stat-dummy
osmo_stat_dummy_SOURCES = osmo-stat-dummy.c
osmo_stat_dummy_LDADD = $(LDADD) $(TALLOC_LIBS) \
			$(top_builddir)/src/vty/libosmovty.la \
			$(top_builddir)/src/ctrl/libosmoctrl.la \
			$(top_builddir)/src/core/libosmocore.la
osmo_stat_dummy_CFLAGS = -Wall $(TALLOC_CFLAGS) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOCTRL_CFLAGS)
osmo_stat_dummy_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
endif
