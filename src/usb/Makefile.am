# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=0:0:0

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -fPIC -Wall $(LIBUSB_CFLAGS) $(TALLOC_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

if ENABLE_LIBUSB

lib_LTLIBRARIES = libosmousb.la

libosmousb_la_SOURCES = osmo_libusb.c
libosmousb_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libosmousb_la_LIBADD = \
	$(top_builddir)/src/libosmocore.la \
	$(TALLOC_LIBS) \
	$(LIBUSB_LIBS)

endif
