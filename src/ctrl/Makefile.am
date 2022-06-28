# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=7:0:7

AM_CFLAGS = -Wall $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/include $(TALLOC_CFLAGS)

if ENABLE_CTRL
lib_LTLIBRARIES = libosmoctrl.la

libosmoctrl_la_SOURCES = control_cmd.c control_if.c fsm_ctrl_commands.c

libosmoctrl_la_LDFLAGS = $(LTLDFLAGS_OSMOCTRL) -version-info $(LIBVERSION) -no-undefined
libosmoctrl_la_LIBADD = $(TALLOC_LIBS) \
	$(top_builddir)/src/libosmocore.la \
	$(top_builddir)/src/gsm/libosmogsm.la \
	$(top_builddir)/src/vty/libosmovty.la

if ENABLE_VTY
libosmoctrl_la_SOURCES += control_vty.c
endif

EXTRA_DIST = libosmoctrl.map

endif
