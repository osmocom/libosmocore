AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -Wall $(TALLOC_CFLAGS) $(PTHREAD_CFLAGS)
AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/src/core/libosmocore.la $(TALLOC_LIBS) $(PTHREAD_LIBS)

check_PROGRAMS = $(top_builddir)/utils/osmo-config-merge \
		 $(NULL)

TESTSUITE = $(srcdir)/testsuite

EXTRA_DIST = testsuite.at \
	     $(srcdir)/package.m4 \
	     $(TESTSUITE) \
	     testA.cfg testA.confmerge testA.ok \
	     testB.cfg testB.confmerge testB.ok \
	     testB2.cfg testB2.confmerge testB2.ok \
	     $(NULL)

DISTCLEANFILES = atconfig

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

update_exp: $(check_PROGRAMS)
	$(top_builddir)/utils/osmo-config-merge $(srcdir)/testA.cfg $(srcdir)/testA.confmerge >$(srcdir)/testA.ok
	$(top_builddir)/utils/osmo-config-merge $(srcdir)/testB.cfg $(srcdir)/testB.confmerge >$(srcdir)/testB.ok
	$(top_builddir)/utils/osmo-config-merge $(srcdir)/testB2.cfg $(srcdir)/testB2.confmerge >$(srcdir)/testB2.ok

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
