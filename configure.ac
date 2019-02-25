AC_INIT([libosmocore],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.6 subdir-objects])
AC_CONFIG_TESTDIR(tests)

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
	LTLDFLAGS_OSMOCODING='-Wl,--version-script=$(srcdir)/libosmocoding.map'
	LTLDFLAGS_OSMOCTRL='-Wl,--version-script=$(srcdir)/libosmoctrl.map'
	;;
esac
AC_SUBST(LTLDFLAGS_OSMOGB)
AC_SUBST(LTLDFLAGS_OSMOGSM)
AC_SUBST(LTLDFLAGS_OSMOCODING)
AC_SUBST(LTLDFLAGS_OSMOCTRL)

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(execinfo.h sys/select.h sys/socket.h sys/timerfd.h syslog.h ctype.h netinet/tcp.h netinet/in.h)
# for src/conv.c
AC_FUNC_ALLOCA
AC_SEARCH_LIBS([dlopen], [dl dld], [LIBRARY_DLOPEN="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DLOPEN)
AC_SEARCH_LIBS([dlsym], [dl dld], [LIBRARY_DLSYM="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DLSYM)
# for src/backtrace.c
AC_CHECK_LIB(execinfo, backtrace, BACKTRACE_LIB=-lexecinfo, BACKTRACE_LIB=)
AC_SUBST(BACKTRACE_LIB)

# check for old glibc < 2.17 to get clock_gettime
AC_SEARCH_LIBS([clock_gettime], [rt posix4], [LIBRARY_RT="$LIBS";LIBS=""])
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

AC_CHECK_FUNCS(clock_gettime localtime_r)

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

dnl Generate the output
AC_CONFIG_HEADER(config.h)

PKG_CHECK_MODULES(TALLOC, [talloc >= 2.0.1])

AC_ARG_ENABLE([pcsc], [AS_HELP_STRING([--disable-pcsc], [Build without PC/SC support])],
    [
        ENABLE_PCSC=$enableval
    ],
    [
        ENABLE_PCSC="yes"
    ])
AS_IF([test "x$ENABLE_PCSC" = "xyes"], [
	PKG_CHECK_MODULES(PCSC, libpcsclite)
])
AM_CONDITIONAL(ENABLE_PCSC, test "x$ENABLE_PCSC" = "xyes")
AC_SUBST(ENABLE_PCSC)

AC_ARG_ENABLE([gnutls], [AS_HELP_STRING([--disable-gnutls], [Do not use GnuTLS fallback for missing getrandom()])],
	[ENABLE_GNUTLS=$enableval], [ENABLE_GNUTLS="yes"])
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

AC_ARG_ENABLE(plugin,
	[AS_HELP_STRING(
		[--disable-plugin],
		[Disable support for dlopen plugins],
	)],
	[enable_plugin=$enableval], [enable_plugin="yes"])
AM_CONDITIONAL(ENABLE_PLUGIN, test x"$enable_plugin" = x"yes")

AC_ARG_ENABLE(vty,
	[AS_HELP_STRING(
		[--disable-vty],
		[Disable building VTY telnet interface]
	)],
	[enable_vty=$enableval], [enable_vty="yes"])
AM_CONDITIONAL(ENABLE_VTY, test x"$enable_vty" = x"yes")

AC_ARG_ENABLE(panic_infloop,
	[AS_HELP_STRING(
		[--enable-panic-infloop],
		[Trigger infinite loop on panic rather than fprintf/abort]
	)],
	[panic_infloop=$enableval], [panic_infloop="no"])
if test x"$panic_infloop" = x"yes"
then
	AC_DEFINE([PANIC_INFLOOP],[1],[Use infinite loop on panic rather than fprintf/abort])
fi

AC_ARG_ENABLE(bsc_fd_check,
	[AS_HELP_STRING(
		[--enable-bsc-fd-check],
		[Instrument bsc_register_fd to check that the fd is registered]
	)],
	[fd_check=$enableval], [fd_check="no"])
if test x"$fd_check" = x"no"
then
	AC_DEFINE([BSC_FD_CHECK],[1],[Instrument the bsc_register_fd])
fi

AC_ARG_ENABLE(msgfile,
	[AS_HELP_STRING(
		[--disable-msgfile],
		[Disable support for the msgfile],
	)],
	[enable_msgfile=$enableval], [enable_msgfile="yes"])
AM_CONDITIONAL(ENABLE_MSGFILE, test x"$enable_msgfile" = x"yes")

AC_ARG_ENABLE(serial,
	[AS_HELP_STRING(
		[--disable-serial],
		[Disable support for the serial helpers],
	)],
	[enable_serial=$enableval], [enable_serial="yes"])
AM_CONDITIONAL(ENABLE_SERIAL, test x"$enable_serial" = x"yes")

AC_ARG_ENABLE(utilities,
        [AS_HELP_STRING(
                [--disable-utilities],
                [Disable building utility programs],
        )],
        [enable_utilities=$enableval], [enable_utilities="yes"])
AM_CONDITIONAL(ENABLE_UTILITIES, test x"$enable_utilities" = x"yes")

AC_ARG_ENABLE(gb,
        [AS_HELP_STRING(
                [--disable-gb],
                [Disable building Gb library],
        )],
        [enable_gb=$enableval], [enable_gb="yes"])
AM_CONDITIONAL(ENABLE_GB, test x"$enable_gb" = x"yes")

AC_ARG_ENABLE(ctrl,
        [AS_HELP_STRING(
                [--disable-ctrl],
                [Disable building CTRL library],
        )],
        [enable_ctrl=$enableval], [enable_ctrl="yes"])
AM_CONDITIONAL(ENABLE_CTRL, test x"$enable_ctrl" = x"yes")

AC_ARG_ENABLE(pseudotalloc,
        [AS_HELP_STRING(
                [--enable-pseudotalloc],
                [Enable building pseudotalloc library],
        )],
        [enable_pseudotalloc=$enableval], [enable_pseudotalloc="no"])
AM_CONDITIONAL(ENABLE_PSEUDOTALLOC, test x"$enable_pseudotalloc" = x"yes")

AC_ARG_ENABLE(embedded,
	[AS_HELP_STRING(
		[--enable-embedded],
		[Enable building for embedded use and disable unsupported features]
	)],
	[embedded=$enableval], [embedded="no"])

AM_CONDITIONAL(ENABLE_STATS_TEST, true)
AM_CONDITIONAL(ENABLE_SERCOM_STUB, false)

if test x"$embedded" = x"yes"
then
	AC_DEFINE([EMBEDDED],[1],[Select building for embedded use])
	AM_CONDITIONAL(ENABLE_PLUGIN, false)
	AM_CONDITIONAL(ENABLE_MSGFILE, false)
	AM_CONDITIONAL(ENABLE_SERIAL, false)
	AM_CONDITIONAL(ENABLE_GNUTLS, false)
	AM_CONDITIONAL(ENABLE_VTY, false)
	AM_CONDITIONAL(ENABLE_CTRL, false)
	AM_CONDITIONAL(ENABLE_UTILITIES, false)
	AM_CONDITIONAL(ENABLE_GB, false)
	AM_CONDITIONAL(ENABLE_GNUTLS, false)
	AM_CONDITIONAL(ENABLE_PCSC, false)
	AM_CONDITIONAL(ENABLE_PSEUDOTALLOC, true)
	AM_CONDITIONAL(ENABLE_SERCOM_STUB, true)
	AM_CONDITIONAL(ENABLE_STATS_TEST, false)
	AC_DEFINE([USE_GNUTLS], [0])
	AC_DEFINE([PANIC_INFLOOP],[1],[Use infinite loop on panic rather than fprintf/abort])
fi

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
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
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmo_verify_transcript_vty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install git://osmocom.org/python/osmo-python-tests to run the VTY/CTRL tests.])
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
	[simd=$enableval], [simd="yes"])
if test x"$simd" = x"yes"
then
	# Find and define supported SIMD extensions
	AX_CHECK_SIMD
else
	AM_CONDITIONAL(HAVE_AVX2, false)
	AM_CONDITIONAL(HAVE_SSSE3, false)
	AM_CONDITIONAL(HAVE_SSE4_1, false)
fi

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

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_OUTPUT(
	libosmocore.pc
	libosmocodec.pc
	libosmocoding.pc
	libosmovty.pc
	libosmogsm.pc
	libosmogb.pc
	libosmoctrl.pc
	libosmosim.pc
	include/Makefile
	src/Makefile
	src/vty/Makefile
	src/codec/Makefile
	src/coding/Makefile
	src/sim/Makefile
	src/gsm/Makefile
	src/gb/Makefile
	src/ctrl/Makefile
	src/pseudotalloc/Makefile
	tests/Makefile
	tests/atlocal
	utils/Makefile
	Doxyfile.core
	Doxyfile.gsm
	Doxyfile.vty
	Doxyfile.codec
	Doxyfile.coding
	Doxyfile.gb
	Doxyfile.ctrl
	Makefile)
