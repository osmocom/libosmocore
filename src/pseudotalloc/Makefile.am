AM_CPPFLAGS = -I. -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -Wall

if ENABLE_PSEUDOTALLOC

lib_LTLIBRARIES = libpseudotalloc.la

libpseudotalloc_la_SOURCES = pseudotalloc.c
libpseudotalloc_la_LDFLAGS = -no-undefined

nobase_include_HEADERS = talloc.h

endif
