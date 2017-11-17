# ===========================================================================
#          http://www.gnu.org/software/autoconf-archive/ax_ext.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_EXT
#
# DESCRIPTION
#
#   Find supported SIMD extensions by requesting cpuid. When an SIMD
#   extension is found, the -m"simdextensionname" is added to SIMD_FLAGS if
#   compiler supports it. For example, if "sse2" is available, then "-msse2"
#   is added to SIMD_FLAGS.
#
#   This macro calls:
#
#     AC_SUBST(SIMD_FLAGS)
#
#   And defines:
#
#      HAVE_AVX3 / HAVE_SSSE3 / HAVE_SSE4.1
#
# LICENSE
#
#   Copyright (c) 2007 Christophe Tournayre <turn3r@users.sourceforge.net>
#   Copyright (c) 2013 Michael Petch <mpetch@capp-sysware.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.
#
# NOTE: The functionality that requests the cpuid has been stripped because
#       this project detects the CPU capabilities during runtime. However, we
#       still need to check if the compiler supports the requested SIMD flag.

#serial 12

AC_DEFUN([AX_CHECK_SIMD],
[
  AC_REQUIRE([AC_CANONICAL_HOST])

  AM_CONDITIONAL(HAVE_AVX2, false)
  AM_CONDITIONAL(HAVE_SSSE3, false)
  AM_CONDITIONAL(HAVE_SSE4_1, false)

  case $host_cpu in
    i[[3456]]86*|x86_64*|amd64*)
      AX_CHECK_COMPILE_FLAG(-mavx2, ax_cv_support_avx2_ext=yes, [])
      if test x"$ax_cv_support_avx2_ext" = x"yes"; then
        SIMD_FLAGS="$SIMD_FLAGS -mavx2"
        AC_DEFINE(HAVE_AVX2,,
          [Support AVX2 (Advanced Vector Extensions 2) instructions])
        AM_CONDITIONAL(HAVE_AVX2, true)
      else
        AC_MSG_WARN([Your compiler does not support AVX2 instructions])
      fi

      AX_CHECK_COMPILE_FLAG(-mssse3, ax_cv_support_ssse3_ext=yes, [])
      if test x"$ax_cv_support_ssse3_ext" = x"yes"; then
        SIMD_FLAGS="$SIMD_FLAGS -mssse3"
        AC_DEFINE(HAVE_SSSE3,,
          [Support SSSE3 (Supplemental Streaming SIMD Extensions 3) instructions])
        AM_CONDITIONAL(HAVE_SSSE3, true)
      else
        AC_MSG_WARN([Your compiler does not support SSSE3 instructions])
      fi

      AX_CHECK_COMPILE_FLAG(-msse4.1, ax_cv_support_sse41_ext=yes, [])
      if test x"$ax_cv_support_sse41_ext" = x"yes"; then
        SIMD_FLAGS="$SIMD_FLAGS -msse4.1"
        AC_DEFINE(HAVE_SSE4_1,,
          [Support SSE4.1 (Streaming SIMD Extensions 4.1) instructions])
        AM_CONDITIONAL(HAVE_SSE4_1, true)
      else
        AC_MSG_WARN([Your compiler does not support SSE4.1 instructions])
      fi
  ;;
  esac

  AC_SUBST(SIMD_FLAGS)
])
