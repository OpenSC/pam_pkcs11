# $Id$

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = -Wall -fno-strict-aliasing $(OPENSSL_CFLAGS)

lib_LTLIBRARIES = pam_pkcs11.la

pam_pkcs11_la_SOURCES =  pam_pkcs11.c  \
			mapper_mgr.c mapper_mgr.h \
			pam_config.c pam_config.h
pam_pkcs11_la_LDFLAGS = -module -avoid-version
pam_pkcs11_la_LIBADD = $(LIBMAPPERS) $(OPENSSL_LIBS)

install:       
	$(mkinstalldirs) $(DESTDIR)/$(libdir)/security
	$(libLTLIBRARIES_INSTALL) $(top_builddir)/src/pam_pkcs11/.libs/pam_pkcs11.so $(DESTDIR)/$(libdir)/security

format:
	indent *.c *.h
