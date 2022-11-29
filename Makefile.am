ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include
SUBDIRS = \
	include \
	src \
	utils \
	tapset \
	tests \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmocore.pc libosmocodec.pc libosmovty.pc libosmogsm.pc \
		 libosmogb.pc libosmoctrl.pc libosmocoding.pc libosmosim.pc \
		 libosmousb.pc libosmoisdn.pc

aclocaldir = $(datadir)/aclocal
dist_aclocal_DATA = m4/osmo_ac_code_coverage.m4 \
					m4/osmo_ax_code_coverage.m4

@RELMAKE@
@CODE_COVERAGE_RULES@

relengdir = $(includedir)
releng_DATA = osmo-release.mk

dist_bin_SCRIPTS = osmo-release.sh

osmo-release.mk: git-version-gen

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

EXTRA_DIST = \
	     .version \
	     README.md \
	     contrib/libosmocore.spec.in \
	     debian \
	     git-version-gen \
	     osmo-release.mk \
	     osmo-release.sh \
	     $(NULL)

HTML = \
	$(top_builddir)/doc/core/html/index.html \
	$(top_builddir)/doc/gsm/html/index.html \
	$(top_builddir)/doc/isdn/html/index.html \
	$(top_builddir)/doc/vty/html/index.html \
	$(top_builddir)/doc/codec/html/index.html \
	$(top_builddir)/doc/coding/html/index.html \
	$(top_builddir)/doc/ctrl/html/index.html \
	$(top_builddir)/doc/gb/html/index.html

if HAVE_DOXYGEN
html_DATA = $(top_builddir)/doc/html.tar

doc: $(html_DATA)

$(html_DATA): apidoc
else
DOXYGEN=doxygen
endif

.PHONY: apidoc
apidoc: $(HTML)
	cd $(top_builddir)/doc && tar cf html.tar */html

# Support doxygen cross references from each library to each other library:
# First generate the docs to make sure all .tag files are in place.
# In a second run, generate the content with proper referencing.
# For example, libosmocore references tags from libosmovty and vice versa,
# so both need to generate tag files first, and then do another run.
#
# Generate each docs tree, and touch a libosmofoo.tag.prep file when done.
# It means that a libosmofoo.tag file is up-to-date.
# Touch a separate "*.prep" target: libosmofoo.tag as target would create
# circular dependency: we would rebuild all every time 'make' is invoked.
# The .prep file also depends on all the source files for that library.

$(top_builddir)/doc/libosmocore.tag.prep: $(top_builddir)/Doxyfile.core \
		$(top_srcdir)/include/osmocom/core/*.h \
		$(top_srcdir)/src/core/*.[hc] \
		$(top_srcdir)/src/core/crcXXgen.c.tpl \
		$(top_srcdir)/src/pseudotalloc/*.[hc]
	rm -rf $(top_builddir)/doc/core; mkdir -p $(top_builddir)/doc/core
	rm -rf $(top_builddir)/doc/libosmocore.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.core
	touch "$@"

$(top_builddir)/doc/libosmogsm.tag.prep: $(top_builddir)/Doxyfile.gsm \
		$(top_srcdir)/include/osmocom/gsm/*.h \
		$(top_srcdir)/include/osmocom/gsm/protocol/*.h \
		$(top_srcdir)/include/osmocom/crypt/*.h \
		$(top_srcdir)/src/gsm/*.c \
		$(top_srcdir)/src/gsm/milenage/*.[hc]
	rm -rf $(top_builddir)/doc/gsm; mkdir -p $(top_builddir)/doc/gsm
	rm -rf $(top_builddir)/doc/libosmogsm.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.gsm
	touch "$@"

$(top_builddir)/doc/libosmoisdn.tag.prep: $(top_builddir)/Doxyfile.isdn \
		$(top_srcdir)/include/osmocom/isdn/*.h \
		$(top_srcdir)/src/isdn/*.c
	rm -rf $(top_builddir)/doc/isdn; mkdir -p $(top_builddir)/doc/isdn
	rm -rf $(top_builddir)/doc/libosmoisdn.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.isdn
	touch "$@"

# Don't delete the entire doc/vty, it contains example.xml and vtydoc.xsd (OS#3986)
$(top_builddir)/doc/libosmovty.tag.prep: $(top_builddir)/Doxyfile.vty \
		$(top_srcdir)/include/osmocom/vty/*.h \
		$(top_srcdir)/src/vty/*.c
	rm -rf $(top_builddir)/doc/vty/html $(top_builddir)/doc/vty/latex
	rm -rf $(top_builddir)/doc/libosmovty.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.vty
	touch "$@"

$(top_builddir)/doc/libosmocodec.tag.prep: $(top_builddir)/Doxyfile.codec \
		$(top_srcdir)/include/osmocom/codec/*.h \
		$(top_srcdir)/src/codec/*.c
	rm -rf $(top_builddir)/doc/codec; mkdir -p $(top_builddir)/doc/codec
	rm -rf $(top_builddir)/doc/libosmocodec.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.codec
	touch "$@"

$(top_builddir)/doc/libosmocoding.tag.prep: $(top_builddir)/Doxyfile.coding \
		$(top_srcdir)/include/osmocom/coding/*.h \
		$(top_srcdir)/src/coding/*.c
	rm -rf $(top_builddir)/doc/coding; mkdir -p $(top_builddir)/doc/coding
	rm -rf $(top_builddir)/doc/libosmocoding.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.coding
	touch "$@"

$(top_builddir)/doc/libosmoctrl.tag.prep: $(top_builddir)/Doxyfile.ctrl \
		$(top_srcdir)/include/osmocom/ctrl/*.h \
		$(top_srcdir)/src/ctrl/*.c
	rm -rf $(top_builddir)/doc/ctrl; mkdir -p $(top_builddir)/doc/ctrl
	rm -rf $(top_builddir)/doc/libosmoctrl.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.ctrl
	touch "$@"

$(top_builddir)/doc/libosmogb.tag.prep: $(top_builddir)/Doxyfile.gb \
		$(top_srcdir)/include/osmocom/gprs/*.h \
		$(top_srcdir)/src/gb/*.[hc]
	rm -rf $(top_builddir)/doc/gb; mkdir -p $(top_builddir)/doc/gb
	rm -rf $(top_builddir)/doc/libosmogb.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.gb
	touch "$@"

# Build for real once all depending .tag files are in place.
# Depend on the own .tag.prep file to avoid concurrent builds of the same doc
# tree, and to also depend on all the source files listed above.
#
# Each library should depend on all the tag.prep files of which it lists .tag
# files in Doxyfile under TAGFILES.
#
# In turn, include all .tag files in TAGFILES of libraries to which "\ref"
# references point.
#
# Easiest is to just depend on all tag.prep files all across everywhere.

$(top_builddir)/doc/core/html/index.html: $(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/core; mkdir -p $(top_builddir)/doc/core
	$(DOXYGEN) Doxyfile.core

$(top_builddir)/doc/gsm/html/index.html: $(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/gsm; mkdir -p $(top_builddir)/doc/gsm
	$(DOXYGEN) Doxyfile.gsm

$(top_builddir)/doc/isdn/html/index.html: $(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/isdn; mkdir -p $(top_builddir)/doc/isdn
	$(DOXYGEN) Doxyfile.isdn

# Don't delete the entire doc/vty, it contains example.xml and vtydoc.xsd (OS#3986)
$(top_builddir)/doc/vty/html/index.html: $(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/vty/html $(top_builddir)/doc/vty/latex
	$(DOXYGEN) Doxyfile.vty

$(top_builddir)/doc/codec/html/index.html: $(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/codec; mkdir -p $(top_builddir)/doc/codec
	$(DOXYGEN) Doxyfile.codec

$(top_builddir)/doc/coding/html/index.html: $(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/coding; mkdir -p $(top_builddir)/doc/coding
	$(DOXYGEN) Doxyfile.coding

$(top_builddir)/doc/ctrl/html/index.html: $(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/ctrl; mkdir -p $(top_builddir)/doc/ctrl
	$(DOXYGEN) Doxyfile.ctrl

$(top_builddir)/doc/gb/html/index.html: $(top_builddir)/doc/libosmogb.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmoisdn.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep
	rm -rf $(top_builddir)/doc/gb; mkdir -p $(top_builddir)/doc/gb
	$(DOXYGEN) Doxyfile.gb

if HAVE_DOXYGEN
install-data-hook:
	cd $(DESTDIR)$(htmldir) && tar xf html.tar && rm -f html.tar

uninstall-hook:
	cd $(DESTDIR)$(htmldir) && rm -rf {core,gsm,isdn,vty,codec,coding,ctrl,gb}

DX_CLEAN = doc/{core,gsm,isdn,vty,codec,coding,ctrl,gb}/html/search/* doc/{core,gsm,isdn,vty,codec,coding,ctrl,gb}/{html,latex}/* doc/html.tar doc/{core,gsm,isdn,vty,codec,coding,ctrl,gb}/doxygen_sqlite3.db doc/*.tag doc/*.tag.prep
endif

MOSTLYCLEANFILES = $(DX_CLEAN)
