if BUILD_MAN
man_MANS =  osmo-config-merge.8
endif

ASCIIDOCS = osmo-config-merge.adoc

A2X_OPTS_MANPAGE = --doctype manpage --format manpage -D ${builddir}

%.8 : %.adoc
		a2x ${A2X_OPTS_MANPAGE} $<

EXTRA_DIST = ${ASCIIDOCS}

CLEANFILES = \
	     osmo-config-merge.8
