# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=3:2:1

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -fPIC -Wall $(TALLOC_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_HEADERS = sim_int.h gsm_int.h

if !EMBEDDED
lib_LTLIBRARIES = libosmosim.la

libosmosim_la_SOURCES = core.c reader.c class_tables.c \
			card_fs_sim.c card_fs_usim.c card_fs_uicc.c \
			card_fs_isim.c card_fs_hpsim.c card_fs_tetra.c
libosmosim_la_LDFLAGS = \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)
libosmosim_la_LIBADD = \
	$(top_builddir)/src/core/libosmocore.la \
	$(top_builddir)/src/gsm/libosmogsm.la \
	$(TALLOC_LIBS)
if ENABLE_PCSC
AM_CFLAGS += $(PCSC_CFLAGS)
libosmosim_la_SOURCES += reader_pcsc.c
libosmosim_la_LIBADD += $(PCSC_LIBS)
endif

endif # !EMBEDDED
