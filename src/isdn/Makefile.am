# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=0:0:0

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -Wall $(TALLOC_CFLAGS)

if ENABLE_PSEUDOTALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/pseudotalloc
endif

noinst_LTLIBRARIES = libisdnint.la
lib_LTLIBRARIES = libosmoisdn.la

libisdnint_la_SOURCES = i460_mux.c lapd_core.c

libisdnint_la_LDFLAGS = -no-undefined
libisdnint_la_LIBADD = $(top_builddir)/src/core/libosmocore.la

libosmoisdn_la_SOURCES =
libosmoisdn_la_LDFLAGS = $(LTLDFLAGS_OSMOISDN) -version-info $(LIBVERSION) -no-undefined
libosmoisdn_la_LIBADD = libisdnint.la $(TALLOC_LIBS)

EXTRA_DIST = libosmoisdn.map
