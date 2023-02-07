# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=15:0:1

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -Wall -fno-strict-aliasing \
	    $(TALLOC_CFLAGS) \
	    $(NULL)

# FIXME: this should eventually go into a milenage/Makefile.am
noinst_HEADERS = common_vty.h gb_internal.h gprs_bssgp_internal.h gprs_ns2_internal.h

if ENABLE_GB
lib_LTLIBRARIES = libosmogb.la

libosmogb_la_LDFLAGS = \
		$(LTLDFLAGS_OSMOGB) \
		-version-info $(LIBVERSION) \
		-no-undefined \
		$(NULL)
libosmogb_la_LIBADD = $(TALLOC_LIBS) \
		$(top_builddir)/src/core/libosmocore.la \
		$(top_builddir)/src/vty/libosmovty.la \
		$(top_builddir)/src/gsm/libosmogsm.la

libosmogb_la_SOURCES = gprs_ns.c gprs_ns_frgre.c gprs_ns_vty.c gprs_ns_sns.c \
		  gprs_bssgp.c gprs_bssgp_util.c gprs_bssgp_vty.c gprs_bssgp_rim.c \
		  gprs_bssgp_bss.c \
		  gprs_ns2.c gprs_ns2_udp.c gprs_ns2_frgre.c gprs_ns2_fr.c gprs_ns2_vc_fsm.c gprs_ns2_sns.c \
		  gprs_ns2_message.c gprs_ns2_vty.c \
		  gprs_bssgp2.c bssgp_bvc_fsm.c \
		  common_vty.c frame_relay.c

# convenience library for testing with access to all non-static symbols
noinst_LTLIBRARIES = libosmogb-test.la
libosmogb_test_la_LIBADD = $(libosmogb_la_LIBADD)
libosmogb_test_la_SOURCES= $(libosmogb_la_SOURCES)

endif

EXTRA_DIST = libosmogb.map
