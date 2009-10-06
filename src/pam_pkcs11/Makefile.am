# $Id$

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = -Wall -fno-strict-aliasing $(CRYPTO_CFLAGS)
AM_CPPFLAGS = -Wall -fno-strict-aliasing $(CRYPTO_CFLAGS)

pamdir=$(libdir)/security

pam_LTLIBRARIES = pam_pkcs11.la
noinst_LTLIBRARIES = libfinder.la

libfinder_la_SOURCES = mapper_mgr.c pam_config.c

pam_pkcs11_la_SOURCES =  pam_pkcs11.c  \
			mapper_mgr.c mapper_mgr.h \
			pam_config.c pam_config.h
pam_pkcs11_la_LDFLAGS = -module -avoid-version -shared
pam_pkcs11_la_LIBADD = ../mappers/libmappers.la $(CRYPTO_LIBS)

format:
	indent *.c *.h
