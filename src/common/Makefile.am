# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = . rsaref

noinst_HEADERS = debug.h error.h uri.h strings.h \
	cert_vfy.h cert_info.h base64.h

noinst_PROGRAMS = 
noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = cert_vfy.c cert_vfy.h \
	cert_info.c cert_info.h \
	debug.c debug.h error.c error.h \
	uri.c uri.h strings.c strings.h \
	pkcs11.c \
	base64.c base64.h

libcommon_la_LIBADD = $(OPENSSL_LIBS)
