# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=16:0:0

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -Wall $(TALLOC_CFLAGS) $(PTHREAD_CFLAGS) $(LIBSCTP_CFLAGS) $(LIBMNL_CFLAGS)

if ENABLE_PSEUDOTALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/pseudotalloc
endif

lib_LTLIBRARIES = libosmocore.la

libosmocore_la_LIBADD = $(BACKTRACE_LIB) $(TALLOC_LIBS) $(LIBRARY_RT) $(PTHREAD_LIBS) $(LIBSCTP_LIBS)
libosmocore_la_SOURCES = context.c timer.c timer_gettimeofday.c timer_clockgettime.c \
			 select.c signal.c msgb.c bits.c \
			 bitvec.c bitcomp.c counter.c fsm.c \
			 write_queue.c utils.c socket.c \
			 logging.c logging_syslog.c logging_gsmtap.c rate_ctr.c \
			 gsmtap_util.c crc16.c panic.c backtrace.c \
			 conv.c application.c rbtree.c strrb.c \
			 loggingrb.c crc8gen.c crc16gen.c crc32gen.c crc64gen.c \
			 macaddr.c stat_item.c stats.c stats_statsd.c prim.c \
			 conv_acc.c conv_acc_generic.c sercomm.c prbs.c \
			 isdnhdlc.c \
			 tdef.c \
			 sockaddr_str.c \
			 use_count.c \
			 exec.c \
			 it_q.c \
			 probes.d \
			 $(NULL)

if HAVE_SSSE3
libosmocore_la_SOURCES += conv_acc_sse.c
if HAVE_SSE4_1
conv_acc_sse.lo : AM_CFLAGS += -mssse3 -msse4.1
else
conv_acc_sse.lo : AM_CFLAGS += -mssse3
endif

if HAVE_AVX2
libosmocore_la_SOURCES += conv_acc_sse_avx.c
if HAVE_SSE4_1
conv_acc_sse_avx.lo : AM_CFLAGS += -mssse3 -mavx2 -msse4.1
else
conv_acc_sse_avx.lo : AM_CFLAGS += -mssse3 -mavx2
endif
endif
endif

if HAVE_NEON
libosmocore_la_SOURCES += conv_acc_neon.c
# conv_acc_neon.lo : AM_CFLAGS += -mfpu=neon no, could as well be vfp with neon
endif

BUILT_SOURCES = crc8gen.c crc16gen.c crc32gen.c crc64gen.c
EXTRA_DIST = conv_acc_sse_impl.h conv_acc_neon_impl.h crcXXgen.c.tpl

libosmocore_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined

if ENABLE_PLUGIN
libosmocore_la_SOURCES += plugin.c
libosmocore_la_LIBADD += $(LIBRARY_DLOPEN)
endif

if ENABLE_MSGFILE
libosmocore_la_SOURCES += msgfile.c
endif

if ENABLE_SERIAL
libosmocore_la_SOURCES += serial.c
endif

if ENABLE_SYSTEMD_LOGGING
libosmocore_la_SOURCES += logging_systemd.c
libosmocore_la_LIBADD += $(SYSTEMD_LIBS)
endif

if ENABLE_LIBMNL
libosmocore_la_SOURCES += mnl.c
libosmocore_la_LIBADD += $(LIBMNL_LIBS)
endif

if ENABLE_SYSTEMTAP
probes.h: probes.d
	$(DTRACE) -C -h -s $< -o $@

probes.lo: probes.d
	$(LIBTOOL) --mode=compile $(AM_V_lt) --tag=CC env CFLAGS="$(CFLAGS)" $(DTRACE) -C -G -s $< -o $@

BUILT_SOURCES += probes.h probes.lo
libosmocore_la_LIBADD += probes.lo
endif

crc%gen.c: crcXXgen.c.tpl
	$(AM_V_GEN)sed -e's/XX/$*/g' $< > $@
