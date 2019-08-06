# OS#4062 (https://osmocom.org/issues/4062)
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81142
# SYS#4628

# Check if We need to apply workaround for TLS bug on ARM platform for GCC < 7.3.0.
# TLS_GCC_ARM_BUG_CFLAGS is filled with required workaround bits if needed.

AC_DEFUN([CHECK_TLS_GCC_ARM_BUG], [
  TLS_GCC_ARM_BUG_CFLAGS=""
  AC_MSG_CHECKING([whether to workaround TLS bug in old gcc on ARM platforms])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[
    #define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
    /* Check for ARM 32 bit and gcc smaller than 7.3.0 */
    /* We need to explicitly exclude GNUC compatible compilers, since they also define GNUC related tokens */
    #if __arm__ && \
        !defined(__clang__) && !defined(__llvm__) && !defined(__INTEL_COMPILER) && \
	defined(__GNUC__) && GCC_VERSION < 70300
    #error TLS bug present!
    #endif
    ]])],
    [tls_bug_present=no],
    [tls_bug_present=yes])
  AS_IF([test "x$tls_bug_present" = "xyes"],[
    TLS_GCC_ARM_BUG_CFLAGS="-mtls-dialect=gnu2"
  ])
  AC_SUBST([TLS_GCC_ARM_BUG_CFLAGS])
  AC_MSG_RESULT([$TLS_GCC_ARM_BUG_CFLAGS])
])

# Allow disabling the check in order to workaround bug by letting user pass
# CFLAGS="-O0" on toolchains that crash when "-mtls-dialect=gnu2" is used.
# CFLAGS is updated with workaround if detection is enabled and workaround is needed.
AC_DEFUN([ARG_ENABLE_DETECT_TLS_GCC_ARM_BUG], [
  AC_ARG_ENABLE(detect_tls_gcc_arm_bug,
    [AS_HELP_STRING(
      [--disable-detect-tls-gcc-arm-bug],
      [Disable detecting and applying workaround for TLS bug on ARM platform for GCC < 7.3.0]
    )],
    [detect_tls_gcc_arm_bug=$enableval], [detect_tls_gcc_arm_bug="yes"])
  if test x"$detect_tls_gcc_arm_bug" = x"yes"; then
    CHECK_TLS_GCC_ARM_BUG
    if test "x$TLS_GCC_ARM_BUG_CFLAGS" != "x"; then
      CFLAGS="$CFLAGS $TLS_GCC_ARM_BUG_CFLAGS"
      AC_MSG_WARN([Applying workaround for TLS bug on ARM platform for GCC < 7.3.0
                  ($TLS_GCC_ARM_BUG_CFLAGS). On some toolchain versions, ld may
                  crash. In that case you must build with CFLAGS='-O0' and run
                  ./configure with --disable-detect-tls-gcc-arm-bug])
    fi
fi
])
