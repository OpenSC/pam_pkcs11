# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = $(CRYPTO_CFLAGS)
AM_CPPFLAGS = $(CRYPTO_CFLAGS)

SUBDIRS = . rsaref

noinst_HEADERS = debug.h error.h uri.h strings.h \
	cert_vfy.h cert_info.h base64.h pkcs11_lib.h \
	cert_st.h alg_st.h SSLerrs.h SECerrs.h NSPRerrs.h

noinst_PROGRAMS = 
noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = algorithm.c cert_vfy.c cert_vfy.h \
	cert_info.c cert_info.h \
	debug.c debug.h error.c error.h \
	uri.c uri.h strings.c strings.h \
	pkcs11_lib.c \
	strndup.c \
	base64.c base64.h

libcommon_la_LIBADD = $(CRYPTO_LIBS) $(PTHREAD_LIBS)
libcommon_la_CFLAGS = $(PTHREAD_CFLAGS)
