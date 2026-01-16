AC_INIT([libosmocore],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.6 subdir-objects])
AC_CONFIG_TESTDIR(tests)
AC_CONFIG_TESTDIR(tests/osmo-config-merge)

CFLAGS="$CFLAGS -std=gnu11"

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT([pic-only disable-static])

AC_CONFIG_MACRO_DIR([m4])

dnl patching ${archive_cmds} to affect generation of file "libtool" to fix linking with clang
AS_CASE(["$LD"],[*clang*],
  [AS_CASE(["${host_os}"],
     [*linux*],[archive_cmds='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'])])

dnl check for pkg-config
dnl * If pkg-config is missing, we get a "syntax error" for PKG_CHECK_MODULES.
dnl   Instead, we want to say that pkg-config and pkg.m4 are missing.
dnl * The proper way is PKG_PROG_PKG_CONFIG() but unfortunately that does not
dnl   produce an intelligible error message if pkg-config is missing entirely
dnl   ("syntax error near unexpected token `0.20'").
dnl * To produce a hint that pkg-config is missing, check for the pkg-config
dnl   binary; but AC_PATH_PROG breaks if the distribution provides only
dnl   prefixed (<arch>-pkg-config) versions, so just print a warning.
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl check os: some linker flags not available on osx
case $host in
*-darwin*)
	;;
*)
	LTLDFLAGS_OSMOGB='-Wl,--version-script=$(srcdir)/libosmogb.map'
	LTLDFLAGS_OSMOGSM='-Wl,--version-script=$(srcdir)/libosmogsm.map'
	LTLDFLAGS_OSMOISDN='-Wl,--version-script=$(srcdir)/libosmoisdn.map'
	LTLDFLAGS_OSMOCODING='-Wl,--version-script=$(srcdir)/libosmocoding.map'
	LTLDFLAGS_OSMOCORE='-Wl,--version-script=$(srcdir)/libosmocore.map'
	LTLDFLAGS_OSMOCTRL='-Wl,--version-script=$(srcdir)/libosmoctrl.map'
	;;
esac
AC_SUBST(LTLDFLAGS_OSMOGB)
AC_SUBST(LTLDFLAGS_OSMOGSM)
AC_SUBST(LTLDFLAGS_OSMOISDN)
AC_SUBST(LTLDFLAGS_OSMOCODING)
AC_SUBST(LTLDFLAGS_OSMOCORE)
AC_SUBST(LTLDFLAGS_OSMOCTRL)

AC_C_BIGENDIAN(
	       [AC_MSG_ERROR([Unfortunately, big endian hosts are currently not supported anymore due to lack of development resources. Contributions welcome.])],
	       [],
	       [AC_MSG_WARN([Byte order could not be determined. Strange.])])

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(execinfo.h poll.h sys/select.h sys/socket.h sys/signalfd.h sys/eventfd.h sys/timerfd.h ctype.h netinet/tcp.h netinet/in.h)
AC_CHECK_DECL(HAVE_SYS_SOCKET_H, AC_SUBST(HAVE_SYS_SOCKET_H, 1), AC_SUBST(HAVE_SYS_SOCKET_H, 0))
# for src/conv.c
AC_FUNC_ALLOCA
AC_SEARCH_LIBS([dlopen], [dl dld], [LIBRARY_DLOPEN="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DLOPEN)
AC_SEARCH_LIBS([dlsym], [dl dld], [LIBRARY_DLSYM="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DLSYM)
# for src/backtrace.c
AC_CHECK_LIB(execinfo, backtrace, BACKTRACE_LIB=-lexecinfo, BACKTRACE_LIB=)
AC_SUBST(BACKTRACE_LIB)

# check for pthread (PTHREAD_CFLAGS, PTHREAD_LIBS)
AX_PTHREAD

AC_MSG_CHECKING(for pthread_getname_np(pthread_t, char*, size_t))
saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
LIBS="$LIBS $PTHREAD_LIBS"
AC_LINK_IFELSE(
	       [AC_LANG_PROGRAM(
		[#define _GNU_SOURCE
		 #include <pthread.h>],
		[pthread_getname_np(pthread_self(),"example",0)])],
	       [AC_MSG_RESULT(yes)
	        AC_DEFINE(HAVE_PTHREAD_GETNAME_NP,1,
		 [Have function pthread_setname_np(const char*)])],
	       [AC_MSG_RESULT(no)])
CFLAGS="$saved_CFLAGS"
LIBS="$saved_LIBS"


# check for old glibc < 2.17 to get clock_gettime
AC_SEARCH_LIBS([clock_gettime], [rt posix4],
	       [AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [Define if clock_gettime is available])
	        LIBRARY_RT="$LIBS";LIBS="";])
AC_SUBST(LIBRARY_RT)

AC_ARG_ENABLE(doxygen,
	[AS_HELP_STRING(
		[--disable-doxygen],
		[Disable generation of documentation using doxygen],
	)],
	[doxygen=$enableval], [doxygen="yes"])
AC_PATH_PROG(DOXYGEN,doxygen,false)
AM_CONDITIONAL(HAVE_DOXYGEN, test $DOXYGEN != false && test "x$doxygen" = "xyes")

# check for syscal fallback on glibc < 2.25 - can be removed once glibc version requirement is bumped
AC_CHECK_DECLS([SYS_getrandom], [], [], [[#include <sys/syscall.h>]])

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

AC_CHECK_FUNCS(localtime_r)

AC_DEFUN([CHECK_TM_INCLUDES_TM_GMTOFF], [
  AC_CACHE_CHECK(
    [whether struct tm has tm_gmtoff member],
    osmo_cv_tm_includes_tm_gmtoff,
    [AC_LINK_IFELSE([
      AC_LANG_PROGRAM([
        #include <time.h>
      ], [
        time_t t = time(NULL);
        struct tm* lt = localtime(&t);
        int off = lt->tm_gmtoff;
      ])
    ],
    osmo_cv_tm_includes_tm_gmtoff=yes,
    osmo_cv_tm_includes_tm_gmtoff=no
    )]
  )
  if test "x$osmo_cv_tm_includes_tm_gmtoff" = xyes; then
    AC_DEFINE(HAVE_TM_GMTOFF_IN_TM, 1,
              [Define if struct tm has tm_gmtoff member.])
  fi
])

CHECK_TM_INCLUDES_TM_GMTOFF

# Check if gettid is available (despite not being documented in glibc doc,
# it requires __USE_GNU on some systems)
# C compiler is used since __USE_GNU seems to be always defined for g++.
save_CPPFLAGS=$CPPFLAGS
AC_LANG_PUSH(C)
CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"
AC_CHECK_FUNCS([gettid])
AC_LANG_POP(C)
CPPFLAGS=$save_CPPFLAGS

dnl Check if We need to apply workaround for TLS bug on ARM platform for GCC < 7.3.0:
ARG_ENABLE_DETECT_TLS_GCC_ARM_BUG

dnl Generate the output
AC_CONFIG_HEADER(config.h)

dnl Search for a Python interpreter on the system
dnl python is needed at built-time for auto-generating code
dnl Don't require a newer version than 3.5 for now, as poky 201705 ships that
dnl Don't require a newer version than 3.4, we build poky 201705 on debian 8
AM_PATH_PYTHON([3.4])

PKG_CHECK_MODULES(TALLOC, [talloc >= 2.1.0])

ENABLE_URING_DEFAULT="yes"
ENABLE_PCSC_DEFAULT="yes"
ENABLE_LIBUSB_DEFAULT="yes"
ENABLE_GNUTLS_DEFAULT="yes"
ENABLE_SYSLOG_LOGGING_DEFAULT="yes"
ENABLE_SYSTEMD_LOGGING_DEFAULT="no"
ENABLE_LIBMNL_DEFAULT="yes"
ENABLE_LIBSCTP_DEFAULT="yes"
ENABLE_SCTP_TESTS_DEFAULT="yes"
ENABLE_URING_TESTS_DEFAULT="yes"
ENABLE_PLUGIN_DEFAULT="yes"
ENABLE_VTY_DEFAULT="yes"
ENABLE_PANIC_INFLOOP_DEFAULT="no"
ENABLE_OSMO_FD_CHECK_DEFAULT="no"
ENABLE_FORCE_IO_SELECT_DEFAULT="no"
ENABLE_MSGFILE_DEFAULT="yes"
ENABLE_SERIAL_DEFAULT="yes"
ENABLE_UTILITIES_DEFAULT="yes"
ENABLE_GB_DEFAULT="yes"
ENABLE_CTRL_DEFAULT="yes"
ENABLE_PSEUDOTALLOC_DEFAULT="no"
ENABLE_EMBEDDED_DEFAULT="no"
ENABLE_LIBOSMOCORE_NO_LOGGING_DEFAULT="no"
ENABLE_SANITIZE_DEFAULT="no"
ENABLE_WERROR_DEFAULT="no"
ENABLE_EXT_TESTS_DEFAULT="no"
ENABLE_SIMD_SUPPORT_DEFAULT="yes"
ENABLE_NEON_SUPPORT_DEFAULT="no"
ENABLE_SYSTEMTAP_DEFAULT="no"

AC_ARG_ENABLE(embedded,
	[AS_HELP_STRING(
		[--enable-embedded],
		[Enable building for embedded use and disable unsupported features]
	)],
	[embedded=$enableval], [embedded=$ENABLE_EMBEDDED_DEFAULT])
AM_CONDITIONAL(EMBEDDED, test x"$embedded" = x"yes")
AM_CONDITIONAL(ENABLE_SERCOM_STUB, test x"$embedded" = x"yes")

if test x"$embedded" = x"yes"
then
	AC_DEFINE([EMBEDDED],[1],[Select building for embedded use])
	ENABLE_PLUGIN_DEFAULT="no"
	ENABLE_MSGFILE_DEFAULT="no"
	ENABLE_SERIAL_DEFAULT="no"
	ENABLE_GNUTLS_DEFAULT="no"
	ENABLE_VTY_DEFAULT="no"
	ENABLE_CTRL_DEFAULT="no"
	ENABLE_UTILITIES_DEFAULT="no"
	ENABLE_GB_DEFAULT="no"
	ENABLE_LIBMNL_DEFAULT="no"
	ENABLE_LIBSCTP_DEFAULT="no"
	ENABLE_LIBUSB_DEFAULT="no"
	ENABLE_PCSC_DEFAULT="no"
	ENABLE_URING_DEFAULT="no"
	ENABLE_PSEUDOTALLOC_DEFAULT="yes"
	ENABLE_SYSLOG_LOGGING_DEFAULT="no"
	ENABLE_PANIC_INFLOOP_DEFAULT="yes"
	ENABLE_GNUTLS_DEFAULT="no"
fi

AC_ARG_ENABLE([uring], [AS_HELP_STRING([--disable-uring], [Build without io_uring support])],
	[ENABLE_URING=$enableval], [ENABLE_URING=$ENABLE_URING_DEFAULT])
AS_IF([test "x$ENABLE_URING" = "xyes"], [
	PKG_CHECK_MODULES(URING, [liburing >= 0.7])
	AC_DEFINE([HAVE_URING],[1],[Build with io_uring support])
])
AM_CONDITIONAL(ENABLE_URING, test "x$ENABLE_URING" = "xyes")
AC_SUBST(ENABLE_URING)

AC_ARG_ENABLE([pcsc], [AS_HELP_STRING([--disable-pcsc], [Build without PC/SC support])],
	[ENABLE_PCSC=$enableval], [ENABLE_PCSC=$ENABLE_PCSC_DEFAULT])
AS_IF([test "x$ENABLE_PCSC" = "xyes"], [
	PKG_CHECK_MODULES(PCSC, libpcsclite)
	AC_DEFINE([HAVE_PCSC],[1],[Build with PC/SC support])
])
AM_CONDITIONAL(ENABLE_PCSC, test "x$ENABLE_PCSC" = "xyes")
AC_SUBST(ENABLE_PCSC)

AC_ARG_ENABLE([libusb], [AS_HELP_STRING([--disable-libusb], [Build without libusb support])],
	[ENABLE_LIBUSB=$enableval], [ENABLE_LIBUSB=$ENABLE_LIBUSB_DEFAULT])
AS_IF([test "x$ENABLE_LIBUSB" = "xyes"], [
	PKG_CHECK_MODULES(LIBUSB, libusb-1.0)
])
AM_CONDITIONAL(ENABLE_LIBUSB, test "x$ENABLE_LIBUSB" = "xyes")
AC_SUBST(ENABLE_LIBUSB)

AC_ARG_ENABLE([gnutls], [AS_HELP_STRING([--disable-gnutls], [Do not use GnuTLS fallback for missing getrandom()])],
	[ENABLE_GNUTLS=$enableval], [ENABLE_GNUTLS=$ENABLE_GNUTLS_DEFAULT])
AM_CONDITIONAL(ENABLE_GNUTLS, test x"$ENABLE_GNUTLS" = x"yes")
AS_IF([test "x$ENABLE_GNUTLS" = "xyes"], [
	PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 2.12.0])
])
AC_SUBST(ENABLE_GNUTLS)
if test x"$ENABLE_GNUTLS" = x"yes"
then
	AC_SUBST([LIBGNUTLS_CFLAGS])
	AC_SUBST([LIBGNUTLS_LIBS])
	AC_DEFINE([USE_GNUTLS], [1], [Use GnuTLS as a fallback for missing getrandom()])
fi

AC_ARG_ENABLE([syslog_logging],
	[AS_HELP_STRING(
		[--disable-syslog-logging],
		[Build without syslog logging support]
	)],
	[syslog_logging=$enableval], [syslog_logging=$ENABLE_SYSLOG_LOGGING_DEFAULT])
AS_IF([test "x$syslog_logging" = "xyes"], [
	AC_CHECK_HEADER([syslog.h], [SYSLOG_H_FOUND='yes'],
			[SYSLOG_H_FOUND='no';
			AC_MSG_ERROR([syslog logging support needs syslog.h header])])
	AC_DEFINE([ENABLE_SYSLOG_LOGGING], [1], [Enable syslog logging target])
])
AM_CONDITIONAL(ENABLE_SYSLOG_LOGGING, test "x$syslog_logging" = "xyes")
AC_SUBST(ENABLE_SYSLOG_LOGGING)

AC_ARG_ENABLE([systemd_logging],
	[AS_HELP_STRING(
		[--enable-systemd-logging],
		[Build with systemd-journal logging support]
	)],
	[systemd_logging=$enableval], [systemd_logging=$ENABLE_SYSTEMD_LOGGING_DEFAULT])
AS_IF([test "x$systemd_logging" = "xyes"], [
	PKG_CHECK_MODULES(SYSTEMD, libsystemd)
	AC_DEFINE([ENABLE_SYSTEMD_LOGGING], [1], [Enable systemd-journal logging target])
])
AM_CONDITIONAL(ENABLE_SYSTEMD_LOGGING, test "x$systemd_logging" = "xyes")
AC_SUBST(ENABLE_SYSTEMD_LOGGING)

AC_ARG_ENABLE([libmnl],
	[AS_HELP_STRING(
		[--disable-libmnl],
		[Build without netlink socket support via libmnl]
	)],
	[mnl=$enableval], [mnl=$ENABLE_LIBMNL_DEFAULT])
AS_IF([test "x$mnl" = "xyes"], [
	PKG_CHECK_MODULES(LIBMNL, libmnl, [AC_SUBST(LIBMNL_PC, [libmnl])])
	AC_DEFINE([ENABLE_LIBMNL], [1], [Enable netlink socket support via libmnl])
])
AM_CONDITIONAL(ENABLE_LIBMNL, test "x$mnl" = "xyes")
AC_SUBST(ENABLE_LIBMNL)

AC_ARG_ENABLE([libsctp], [AS_HELP_STRING([--disable-libsctp], [Do not enable socket multiaddr APIs requiring libsctp])],
	[ENABLE_LIBSCTP=$enableval], [ENABLE_LIBSCTP=$ENABLE_LIBSCTP_DEFAULT])
AM_CONDITIONAL(ENABLE_LIBSCTP, test x"$ENABLE_LIBSCTP" = x"yes")
AS_IF([test "x$ENABLE_LIBSCTP" = "xyes"], [
	AC_DEFINE(HAVE_LIBSCTP, 1, [Define 1 to enable SCTP support])
	# Attempt finding .pc, otherwise set manually (<1.0.17 have no .pc file)
	PKG_CHECK_MODULES(LIBSCTP, libsctp,
		[AC_SUBST(LIBSCTP_PC, [libsctp])],
		[
		AC_MSG_NOTICE([libsctp.pc not found (building against <1.0.17 ?), attempting manual lib lookup])
		old_LIBS=$LIBS
		AC_SEARCH_LIBS([sctp_bindx], [sctp], [
			AC_SUBST(HAVE_LIBSCTP, [1])
			if test -n "$ac_lib"; then
				AC_SUBST(LIBSCTP_LIBS, [-l$ac_lib])
			fi
			], [
			AC_MSG_ERROR([sctp_bindx not found in searched libs])])
		LIBS=$old_LIBS
	])
])

AC_ARG_ENABLE([sctp-tests], [AS_HELP_STRING([--disable-sctp-tests], [Do not run socket tests requiring system SCTP support])],
	[ENABLE_SCTP_TESTS=$enableval], [ENABLE_SCTP_TESTS=$ENABLE_SCTP_TESTS_DEFAULT])
AM_CONDITIONAL(ENABLE_SCTP_TESTS, test x"$ENABLE_SCTP_TESTS" = x"yes")

AC_ARG_ENABLE([uring-tests], [AS_HELP_STRING([--disable-uring-tests], [Do not run io_uring tests])],
	[ENABLE_URING_TESTS=$enableval], [ENABLE_URING_TESTS=$ENABLE_URING_TESTS_DEFAULT])
AM_CONDITIONAL(ENABLE_URING_TESTS, test x"$ENABLE_URING_TESTS" = x"yes")
AC_SUBST(ENABLE_URING_TESTS)

AC_ARG_ENABLE(plugin,
	[AS_HELP_STRING(
		[--disable-plugin],
		[Disable support for dlopen plugins],
	)],
	[enable_plugin=$enableval], [enable_plugin=$ENABLE_PLUGIN_DEFAULT])
AM_CONDITIONAL(ENABLE_PLUGIN, test x"$enable_plugin" = x"yes")

AC_ARG_ENABLE(vty,
	[AS_HELP_STRING(
		[--disable-vty],
		[Disable building VTY telnet interface]
	)],
	[enable_vty=$enableval], [enable_vty=$ENABLE_VTY_DEFAULT])
AM_CONDITIONAL(ENABLE_VTY, test x"$enable_vty" = x"yes")

AC_ARG_ENABLE(panic_infloop,
	[AS_HELP_STRING(
		[--enable-panic-infloop],
		[Trigger infinite loop on panic rather than fprintf/abort]
	)],
	[panic_infloop=$enableval], [panic_infloop=$ENABLE_PANIC_INFLOOP_DEFAULT])
if test x"$panic_infloop" = x"yes"
then
	AC_DEFINE([PANIC_INFLOOP],[1],[Use infinite loop on panic rather than fprintf/abort])
fi

AC_ARG_ENABLE(bsc_fd_check,
	[AS_HELP_STRING(
		[--enable-ofd-check],
		[Instrument osmo_fd_register to check that the fd is registered]
	)],
	[fd_check=$enableval], [fd_check=$ENABLE_OSMO_FD_CHECK_DEFAULT])
if test x"$fd_check" = x"yes"
then
	AC_DEFINE([OSMO_FD_CHECK], [1], [Instrument the osmo_fd_register])
fi

AC_ARG_ENABLE([force_io_select],
	[AS_HELP_STRING(
		[--enable-force-io-select],
		[Build with old select I/O instead of poll]
	)],
	[force_io_select=$enableval], [force_io_select=$ENABLE_FORCE_IO_SELECT_DEFAULT])
AS_IF([test "x$force_io_select" = "xyes"], [
	AC_DEFINE([FORCE_IO_SELECT], [1], [Force the use of select() instead of poll()])
])

AC_ARG_ENABLE(msgfile,
	[AS_HELP_STRING(
		[--disable-msgfile],
		[Disable support for the msgfile],
	)],
	[enable_msgfile=$enableval], [enable_msgfile=$ENABLE_MSGFILE_DEFAULT])
AM_CONDITIONAL(ENABLE_MSGFILE, test x"$enable_msgfile" = x"yes")

AC_ARG_ENABLE(serial,
	[AS_HELP_STRING(
		[--disable-serial],
		[Disable support for the serial helpers],
	)],
	[enable_serial=$enableval], [enable_serial=$ENABLE_SERIAL_DEFAULT])
AM_CONDITIONAL(ENABLE_SERIAL, test x"$enable_serial" = x"yes")

AC_ARG_ENABLE(utilities,
        [AS_HELP_STRING(
                [--disable-utilities],
                [Disable building utility programs],
        )],
        [enable_utilities=$enableval], [enable_utilities=$ENABLE_UTILITIES_DEFAULT])
AM_CONDITIONAL(ENABLE_UTILITIES, test x"$enable_utilities" = x"yes")

AC_ARG_ENABLE(gb,
        [AS_HELP_STRING(
                [--disable-gb],
                [Disable building Gb library],
        )],
        [enable_gb=$enableval], [enable_gb=$ENABLE_GB_DEFAULT])
AM_CONDITIONAL(ENABLE_GB, test x"$enable_gb" = x"yes")

AC_ARG_ENABLE(ctrl,
        [AS_HELP_STRING(
                [--disable-ctrl],
                [Disable building CTRL library],
        )],
        [enable_ctrl=$enableval], [enable_ctrl=$ENABLE_CTRL_DEFAULT])
AM_CONDITIONAL(ENABLE_CTRL, test x"$enable_ctrl" = x"yes")

AC_ARG_ENABLE(pseudotalloc,
        [AS_HELP_STRING(
                [--enable-pseudotalloc],
                [Enable building pseudotalloc library],
        )],
        [enable_pseudotalloc=$enableval], [enable_pseudotalloc=$ENABLE_PSEUDOTALLOC_DEFAULT])
AM_CONDITIONAL(ENABLE_PSEUDOTALLOC, test x"$enable_pseudotalloc" = x"yes")
AS_IF([test "x$enable_pseudotalloc" = "xyes"], [
	AC_DEFINE([ENABLE_PSEUDOTALLOC], [1], [Enable building pseudotalloc library])
])

AC_ARG_ENABLE(log_macros,
	[AS_HELP_STRING(
		[--disable-log-macros],
		[Disable logging macros that are also used internally to print information]
	)],
	[log_macros=$enableval], [log_macros=$ENABLE_LIBOSMOCORE_NO_LOGGING_DEFAULT])
if test x"$log_macros" == x"yes"
then
	AC_DEFINE([LIBOSMOCORE_NO_LOGGING],[1],[Disable logging macros])
fi

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize=$ENABLE_SANITIZE_DEFAULT])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror=$ENABLE_WERROR_DEFAULT])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Werror=implicit-int -Werror=int-conversion -Werror=old-style-definition"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests=$ENABLE_EXT_TESTS_DEFAULT])
if test "x$enable_ext_tests" = "xyes" ; then
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmo_verify_transcript_vty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install https://gitea.osmocom.org/cellular-infrastructure/osmo-python-tests to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

CFLAGS="$CFLAGS -DBUILDING_LIBOSMOCORE -Wall"
CPPFLAGS="$CPPFLAGS -DBUILDING_LIBOSMOCORE -Wall"

AC_ARG_ENABLE(simd,
	[AS_HELP_STRING(
		[--disable-simd],
		[Disable SIMD support]
	)],
	[simd=$enableval], [simd=$ENABLE_SIMD_SUPPORT_DEFAULT])
if test x"$simd" = x"yes"
then
	# Find and define supported SIMD extensions
	AX_CHECK_SIMD
else
	AM_CONDITIONAL(HAVE_AVX2, false)
	AM_CONDITIONAL(HAVE_SSSE3, false)
	AM_CONDITIONAL(HAVE_SSE4_1, false)
fi

AC_ARG_ENABLE(neon,
	[AS_HELP_STRING(
		[--enable-neon],
		[Enable ARM NEON instructions support [default=no]]
	)],
	[neon=$enableval], [neon=$ENABLE_NEON_SUPPORT_DEFAULT])
AS_IF([test "x$neon" = "xyes"], [
	AC_DEFINE([HAVE_NEON],, [Support ARM NEON instructions])
])
AC_MSG_CHECKING([whether to enable ARM NEON instructions support])
AC_MSG_RESULT([$neon])
AM_CONDITIONAL(HAVE_NEON, [test "x$neon" != "xno"])

#
# SystemTap support
#
AC_MSG_CHECKING([whether to include systemtap tracing support])
AC_ARG_ENABLE([systemtap],
	      [AS_HELP_STRING([--enable-systemtap],
			      [Enable inclusion of systemtap trace support])],
	      [ENABLE_SYSTEMTAP="${enableval}"], [ENABLE_SYSTEMTAP=$ENABLE_SYSTEMTAP_DEFAULT])
AM_CONDITIONAL([ENABLE_SYSTEMTAP], [test x$ENABLE_SYSTEMTAP = xyes])
AC_MSG_RESULT(${ENABLE_SYSTEMTAP})

if test "x${ENABLE_SYSTEMTAP}" = xyes; then
  # Additional configuration for --enable-systemtap is HERE
  AC_CHECK_PROGS(DTRACE, dtrace)
  if test -z "$DTRACE"; then
    AC_MSG_ERROR([dtrace not found])
  fi
  AC_CHECK_HEADER([sys/sdt.h], [SDT_H_FOUND='yes'],
                [SDT_H_FOUND='no';
                   AC_MSG_ERROR([systemtap support needs sys/sdt.h header])])
  AC_DEFINE([HAVE_SYSTEMTAP], [1], [Define to 1 if using SystemTap probes.])
  AC_ARG_WITH([tapset-install-dir],
	      [AS_HELP_STRING([--with-tapset-install-dir],
	         [The absolute path where the tapset dir will be installed])],
	      [if test "x${withval}" = x; then
		 ABS_TAPSET_DIR="\$(datadir)/systemtap/tapset"
	       else
		 ABS_TAPSET_DIR="${withval}"
	       fi], [ABS_TAPSET_DIR="\$(datadir)/systemtap/tapset"])
  AC_SUBST(ABS_TAPSET_DIR)
fi


OSMO_AC_CODE_COVERAGE

dnl Check if the compiler supports specified GCC's built-in function
AC_DEFUN([CHECK_BUILTIN_SUPPORT], [
  AC_CACHE_CHECK(
    [whether ${CC} has $1 built-in],
    [osmo_cv_cc_has_builtin], [
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([], [
          __builtin_cpu_supports("sse");
        ])
      ],
      [AS_VAR_SET([osmo_cv_cc_has_builtin], [yes])],
      [AS_VAR_SET([osmo_cv_cc_has_builtin], [no])])
    ]
  )

  AS_IF([test yes = AS_VAR_GET([osmo_cv_cc_has_builtin])], [
    AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_$1), 1,
      [Define to 1 if compiler has the '$1' built-in function])
  ], [
    AC_MSG_WARN($2)
  ])
])

dnl Check if the compiler supports runtime SIMD detection
CHECK_BUILTIN_SUPPORT([__builtin_cpu_supports],
  [Runtime SIMD detection will be disabled])

dnl There are some members in struct tcp_info that might not exist on all linux versions
AC_CHECK_MEMBER([struct tcp_info.tcpi_notsent_bytes],
		AC_DEFINE([HAVE_TCP_INFO_TCPI_NOTSENT_BYTES],
		[1],
		[Define to 1 if your <linux/tcp.h> header file have the tcpi_notsent_bytes member in struct tcp_info]),
		[],
		[#include <linux/tcp.h>])

AC_CHECK_MEMBER([struct tcp_info.tcpi_rwnd_limited],
		AC_DEFINE([HAVE_TCP_INFO_TCPI_RWND_LIMITED],
		[1],
		[Define to 1 if your <linux/tcp.h> header file have the tcpi_rwnd_limited member in struct tcp_info]),
		[],
		[#include <linux/tcp.h>])

AC_CHECK_MEMBER([struct tcp_info.tcpi_sndbuf_limited],
		AC_DEFINE([HAVE_TCP_INFO_TCPI_SNDBUF_LIMITED],
		[1],
		[Define to 1 if your <linux/tcp.h> header file have the tcpi_sndbuf_limited member in struct tcp_info]),
		[],
		[#include <linux/tcp.h>])

AC_CHECK_MEMBER([struct tcp_info.tcpi_reord_seen],
		AC_DEFINE([HAVE_TCP_INFO_TCPI_REORD_SEEN],
		[1],
		[Define to 1 if your <linux/tcp.h> header file have the tcpi_reord_seen member in struct tcp_info]),
		[],
		[#include <linux/tcp.h>])

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_OUTPUT(
	libosmocore.pc
	libosmocodec.pc
	libosmocoding.pc
	libosmovty.pc
	libosmogsm.pc
	libosmoisdn.pc
	libosmogb.pc
	libosmoctrl.pc
	libosmosim.pc
	libosmousb.pc
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/codec/Makefile
	include/osmocom/coding/Makefile
	include/osmocom/core/Makefile
	include/osmocom/crypt/Makefile
	include/osmocom/ctrl/Makefile
	include/osmocom/gprs/Makefile
	include/osmocom/gprs/protocol/Makefile
	include/osmocom/gsm/Makefile
	include/osmocom/gsm/protocol/Makefile
	include/osmocom/isdn/Makefile
	include/osmocom/sim/Makefile
	include/osmocom/usb/Makefile
	include/osmocom/vty/Makefile
	src/Makefile
	src/core/Makefile
	src/vty/Makefile
	src/codec/Makefile
	src/coding/Makefile
	src/sim/Makefile
	src/usb/Makefile
	src/gsm/Makefile
	src/isdn/Makefile
	src/gb/Makefile
	src/ctrl/Makefile
	src/pseudotalloc/Makefile
	tapset/Makefile
	tests/Makefile
	tests/osmo-config-merge/Makefile
	utils/Makefile
	utils/osmo-stat-dummy/Makefile
	Doxyfile.core
	Doxyfile.gsm
	Doxyfile.isdn
	Doxyfile.vty
	Doxyfile.codec
	Doxyfile.coding
	Doxyfile.gb
	Doxyfile.ctrl
	Doxyfile.sim
	Doxyfile.usb
	Makefile
	contrib/libosmocore.spec)
