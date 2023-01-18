# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=2:0:2

AM_CPPFLAGS = \
	-I"$(top_srcdir)/include" \
	-I"$(top_builddir)/include" \
	-I"$(top_builddir)" \
	$(NULL)
AM_CFLAGS = -Wall $(TALLOC_CFLAGS)

if ENABLE_PSEUDOTALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/pseudotalloc
endif

lib_LTLIBRARIES = libosmocoding.la

libosmocoding_la_SOURCES = \
	gsm0503_interleaving.c \
	gsm0503_mapping.c \
	gsm0503_tables.c \
	gsm0503_parity.c \
	gsm0503_coding.c \
	gsm0503_amr_dtx.c
libosmocoding_la_LDFLAGS = \
	$(LTLDFLAGS_OSMOCODING) \
	-version-info \
	$(LIBVERSION) \
	-no-undefined \
	$(TALLOC_LIBS)

libosmocoding_la_LIBADD = \
	$(top_builddir)/src/core/libosmocore.la \
	$(top_builddir)/src/gsm/libosmogsm.la \
	$(top_builddir)/src/codec/libosmocodec.la \
	$(NULL)

EXTRA_DIST = libosmocoding.map
