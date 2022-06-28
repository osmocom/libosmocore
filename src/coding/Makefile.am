# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=2:0:2

AM_CPPFLAGS = \
	-I"$(top_srcdir)/include" \
	-I"$(top_builddir)/include" \
	$(TALLOC_CFLAGS)
AM_CFLAGS = -Wall

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
	../libosmocore.la \
	../gsm/libosmogsm.la \
	../codec/libosmocodec.la

EXTRA_DIST = libosmocoding.map
