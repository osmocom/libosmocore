# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=3:1:3

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -Wall $(TALLOC_CFLAGS)

if ENABLE_PSEUDOTALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/pseudotalloc
endif


lib_LTLIBRARIES = libosmocodec.la

libosmocodec_la_SOURCES = gsm610.c gsm620.c gsm660.c gsm690.c ecu.c ecu_fr.c
libosmocodec_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libosmocodec_la_LIBADD = $(top_builddir)/src/core/libosmocore.la
