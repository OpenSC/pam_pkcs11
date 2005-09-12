# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

DISTCLEANFILES = lex-parse.c
EXTRA_DIST = README.scconf lex-parse.l

noinst_HEADERS = internal.h scconf.h
#noinst_PROGRAMS = test-conf
noinst_LTLIBRARIES = libscconf.la

libscconf_la_SOURCES = scconf.h internal.h scconf.c parse.c write.c sclex.c

#test_conf_SOURCES = test-conf.c
#test_conf_LDADD = libscconf.la
