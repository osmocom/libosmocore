# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=0:1:0

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -fPIC -Wall $(LIBUSB_CFLAGS) $(TALLOC_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

if ENABLE_LIBUSB

lib_LTLIBRARIES = libosmousb.la

libosmousb_la_SOURCES = osmo_libusb.c
libosmousb_la_LDFLAGS = \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)
libosmousb_la_LIBADD = \
	$(top_builddir)/src/core/libosmocore.la \
	$(TALLOC_LIBS) \
	$(LIBUSB_LIBS)

endif
