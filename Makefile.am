ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include src src/vty src/codec src/gsm src/coding src/gb src/ctrl src/sim src/pseudotalloc utils tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmocore.pc libosmocodec.pc libosmovty.pc libosmogsm.pc \
		 libosmogb.pc libosmoctrl.pc libosmocoding.pc libosmosim.pc

@RELMAKE@

relengdir = $(includedir)
releng_DATA = osmo-release.mk

dist_bin_SCRIPTS = osmo-release.sh

osmo-release.mk: git-version-gen

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

EXTRA_DIST = git-version-gen .version README.md osmo-release.mk osmo-release.sh

if HAVE_DOXYGEN

html_DATA = $(top_builddir)/doc/html.tar

doc: $(html_DATA)

$(html_DATA): $(top_builddir)/doc/core/html/index.html \
		  $(top_builddir)/doc/gsm/html/index.html \
		  $(top_builddir)/doc/vty/html/index.html \
		  $(top_builddir)/doc/codec/html/index.html \
		  $(top_builddir)/doc/coding/html/index.html \
		  $(top_builddir)/doc/ctrl/html/index.html \
		  $(top_builddir)/doc/gb/html/index.html
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

$(top_builddir)/doc/libosmocore.tag.prep: $(top_builddir)/Doxyfile.core
	rm -rf $(top_builddir)/doc/core; mkdir -p $(top_builddir)/doc/core
	rm -rf $(top_builddir)/doc/libosmocore.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.core
	touch "$@"

$(top_builddir)/doc/libosmogsm.tag.prep: $(top_builddir)/Doxyfile.gsm
	rm -rf $(top_builddir)/doc/gsm; mkdir -p $(top_builddir)/doc/gsm
	rm -rf $(top_builddir)/doc/libosmogsm.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.gsm
	touch "$@"

$(top_builddir)/doc/libosmovty.tag.prep: $(top_builddir)/Doxyfile.vty
	rm -rf $(top_builddir)/doc/vty; mkdir -p $(top_builddir)/doc/vty
	rm -rf $(top_builddir)/doc/libosmovty.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.vty
	touch "$@"

$(top_builddir)/doc/libosmocodec.tag.prep: $(top_builddir)/Doxyfile.codec
	rm -rf $(top_builddir)/doc/codec; mkdir -p $(top_builddir)/doc/codec
	rm -rf $(top_builddir)/doc/libosmocodec.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.codec
	touch "$@"

$(top_builddir)/doc/libosmocoding.tag.prep: $(top_builddir)/Doxyfile.coding
	rm -rf $(top_builddir)/doc/coding; mkdir -p $(top_builddir)/doc/coding
	rm -rf $(top_builddir)/doc/libosmocoding.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.coding
	touch "$@"

$(top_builddir)/doc/libosmoctrl.tag.prep: $(top_builddir)/Doxyfile.ctrl
	rm -rf $(top_builddir)/doc/ctrl; mkdir -p $(top_builddir)/doc/ctrl
	rm -rf $(top_builddir)/doc/libosmoctrl.map
	-$(DOXYGEN) $(top_builddir)/Doxyfile.ctrl
	touch "$@"

$(top_builddir)/doc/libosmogb.tag.prep: $(top_builddir)/Doxyfile.gb
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
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/core; mkdir -p $(top_builddir)/doc/core
	$(DOXYGEN) Doxyfile.core

$(top_builddir)/doc/gsm/html/index.html: $(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/gsm; mkdir -p $(top_builddir)/doc/gsm
	$(DOXYGEN) Doxyfile.gsm

$(top_builddir)/doc/vty/html/index.html: $(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/vty; mkdir -p $(top_builddir)/doc/vty
	$(DOXYGEN) Doxyfile.vty

$(top_builddir)/doc/codec/html/index.html: $(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/codec; mkdir -p $(top_builddir)/doc/codec
	$(DOXYGEN) Doxyfile.codec

$(top_builddir)/doc/coding/html/index.html: $(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/coding; mkdir -p $(top_builddir)/doc/coding
	$(DOXYGEN) Doxyfile.coding

$(top_builddir)/doc/ctrl/html/index.html: $(top_builddir)/doc/libosmoctrl.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmogb.tag.prep
	rm -rf $(top_builddir)/doc/ctrl; mkdir -p $(top_builddir)/doc/ctrl
	$(DOXYGEN) Doxyfile.ctrl

$(top_builddir)/doc/gb/html/index.html: $(top_builddir)/doc/libosmogb.tag.prep \
		$(top_builddir)/doc/libosmocore.tag.prep \
		$(top_builddir)/doc/libosmogsm.tag.prep \
		$(top_builddir)/doc/libosmovty.tag.prep \
		$(top_builddir)/doc/libosmocodec.tag.prep \
		$(top_builddir)/doc/libosmocoding.tag.prep \
		$(top_builddir)/doc/libosmoctrl.tag.prep
	rm -rf $(top_builddir)/doc/gb; mkdir -p $(top_builddir)/doc/gb
	$(DOXYGEN) Doxyfile.gb

install-data-hook:
	cd $(DESTDIR)$(htmldir) && tar xf html.tar && rm -f html.tar

uninstall-hook:
	cd $(DESTDIR)$(htmldir) && rm -rf {core,gsm,vty,codec,coding,ctrl,gb}

DX_CLEAN = doc/{core,gsm,vty,codec,coding,ctrl,gb}/html/search/* doc/{core,gsm,vty,codec,coding,ctrl,gb}/{html,latex}/* doc/html.tar doc/{core,gsm,vty,codec,coding,ctrl,gb}/doxygen_sqlite3.db doc/*.tag doc/*.tag.prep
endif

MOSTLYCLEANFILES = $(DX_CLEAN)
