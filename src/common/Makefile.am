# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = 
EXTRA_DIST = 

noinst_HEADERS = debug.h error.h uri.h strings.h \
	pkcs11.h pkcs11f.h pkcs11t.h \
	cert_vfy.h cert_info.h

noinst_PROGRAMS = 
noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = cert_vfy.c cert_info.c \
		debug.c error.c uri.c strings.c \
		pkcs11.c
