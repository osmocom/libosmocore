# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=13:2:0

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir) \
	$(NULL)
AM_CFLAGS = \
	-Wall \
	$(TALLOC_CFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(NULL)

if ENABLE_VTY
lib_LTLIBRARIES = libosmovty.la

libosmovty_la_SOURCES = \
	buffer.c \
	command.c \
	cpu_sched_vty.c \
	fsm_vty.c \
	logging_vty.c \
	misc_vty.c \
	stats_vty.c \
	talloc_ctx_vty.c \
	tdef_vty.c \
	telnet_interface.c \
	utils.c \
	vector.c \
	vty.c \
	$(NULL)

libosmovty_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libosmovty_la_LIBADD = \
	$(top_builddir)/src/core/libosmocore.la \
	$(TALLOC_LIBS) \
	$(PTHREAD_LIBS) \
	$(NULL)
endif
