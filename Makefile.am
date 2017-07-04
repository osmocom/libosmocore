ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include src src/vty src/codec src/gsm src/coding src/gb src/ctrl src/sim src/pseudotalloc utils tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmocore.pc libosmocodec.pc libosmovty.pc libosmogsm.pc \
		 libosmogb.pc libosmoctrl.pc libosmocoding.pc

@RELMAKE@

relengdir = $(includedir)
releng_DATA = osmo-release.mk

osmo-release.mk: git-version-gen

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

EXTRA_DIST = git-version-gen .version README.md osmo-release.mk

if HAVE_DOXYGEN

html_DATA = $(top_builddir)/doc/html.tar

doc: $(html_DATA)

$(html_DATA): $(top_builddir)/doc/core/html/index.html \
		  $(top_builddir)/doc/gsm/html/index.html \
		  $(top_builddir)/doc/vty/html/index.html \
		  $(top_builddir)/doc/codec/html/index.html \
		  $(top_builddir)/doc/coding/html/index.html \
		  $(top_builddir)/doc/gb/html/index.html
	cd $(top_builddir)/doc && tar cf html.tar */html

$(top_builddir)/doc/core/html/index.html: $(SOURCES) Doxyfile.core
	@rm -rf doc/core
	mkdir -p doc/core
	$(DOXYGEN) Doxyfile.core

$(top_builddir)/doc/gsm/html/index.html: $(SOURCES) Doxyfile.gsm
	@rm -rf doc/gsm
	mkdir -p doc/gsm
	$(DOXYGEN) Doxyfile.gsm

$(top_builddir)/doc/vty/html/index.html: $(SOURCES) Doxyfile.vty
	@rm -rf doc/vty/{html,latex}
	$(DOXYGEN) Doxyfile.vty

$(top_builddir)/doc/codec/html/index.html: $(SOURCES) Doxyfile.codec
	@rm -rf doc/codec
	mkdir -p doc/codec
	$(DOXYGEN) Doxyfile.codec

$(top_builddir)/doc/coding/html/index.html: Doxyfile.coding
	@rm -rf doc/coding
	mkdir -p doc/coding
	$(DOXYGEN) Doxyfile.coding

$(top_builddir)/doc/gb/html/index.html: $(SOURCES) Doxyfile.gb
	@rm -rf doc/gb
	mkdir -p doc/gb
	$(DOXYGEN) Doxyfile.gb

install-data-hook:
	cd $(DESTDIR)$(htmldir) && tar xf html.tar && rm -f html.tar

uninstall-hook:
	cd $(DESTDIR)$(htmldir) && rm -rf {core,gsm,vty,codec,coding,gb}

DX_CLEAN = doc/{core,gsm,vty,codec,coding,gb}/html/search/* doc/{core,gsm,vty,codec,coding,gb}/{html,latex}/* doc/html.tar doc/{core,gsm,vty,codec,coding,gb}/doxygen_sqlite3.db doc/*.tag
endif

MOSTLYCLEANFILES = $(DX_CLEAN)
