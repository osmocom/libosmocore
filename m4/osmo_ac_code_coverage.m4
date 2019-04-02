AC_DEFUN([OSMO_AC_CODE_COVERAGE],[
	dnl Check for --enable-code-coverage
	AC_REQUIRE([OSMO_AX_CODE_COVERAGE])
	AC_REQUIRE([AX_CHECK_COMPILE_FLAG])

	AS_IF([ test "x$enable_code_coverage" = "xyes" ], [
		# Check whether --coverage flags is supported and add it to CFLAGS
		# When it is not supported add CODE_COVERAGE_CFLAGS to CFLAGS instead
		AX_CHECK_COMPILE_FLAG([--coverage],
			[CFLAGS="$CFLAGS -O0 -g --coverage"],
			[CFLAGS="$CFLAGS $CODE_COVERAGE_CFLAGS"])

		# Add both the absolute source and build directories to the coverage directories.
		CODE_COVERAGE_DIRECTORY='$(abspath $(abs_top_srcdir)) $(abspath $(abs_top_builddir))'
		AC_SUBST(CODE_COVERAGE_DIRECTORY)

		# Enable branch coverage by default
		CODE_COVERAGE_BRANCH_COVERAGE='1'
		AC_SUBST(CODE_COVERAGE_BRANCH_COVERAGE)

		# Exclude external files by default
		CODE_COVERAGE_LCOV_OPTIONS='$(CODE_COVERAGE_LCOV_OPTIONS_DEFAULT) --no-external'
		AC_SUBST(CODE_COVERAGE_LCOV_OPTIONS)

		# Exclude tests sources from the coverage report
		CODE_COVERAGE_IGNORE_PATTERN='"$(abspath $(abs_top_srcdir))/tests/*"'
		AC_SUBST(CODE_COVERAGE_IGNORE_PATTERN)

		# lcov_cobertura is needed only when you want to export the coverage report in
		# the Cobertura's XML format supported by Jenkin's Cobertura plugin
		AC_CHECK_PROG([LCOV_COBERTURA], [lcov_cobertura], [lcov_cobertura])
		AS_IF([test "x$LCOV_COBERTURA" != "xno"], [m4_pattern_allow([AM_V_GEN]) CODE_COVERAGE_RULES+='
coverage-cobertura.xml: $(CODE_COVERAGE_OUTPUT_FILE)
	$(AM_V_GEN)$(LCOV_COBERTURA) -b $(top_srcdir) -o $$@@ $(CODE_COVERAGE_OUTPUT_FILE)

.PHONY: code-coverage-cobertura
code-coverage-cobertura: code-coverage-capture coverage-cobertura.xml
'
		], [CODE_COVERAGE_RULES+='
.PHONY: code-coverage-cobertura
code-coverage-cobertura:
	@echo "Need to install lcov_cobertura"
'
		])
	], [CODE_COVERAGE_RULES+='
.PHONY: code-coverage-cobertura
code-coverage-cobertura:
	@echo "Need to and reconfigure with --enable-code-coverage"
'
	])
])
