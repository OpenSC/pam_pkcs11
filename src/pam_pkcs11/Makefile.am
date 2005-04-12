# $Id$

AM_CFLAGS = -Wall -fno-strict-aliasing

lib_LTLIBRARIES = pam_pkcs11.la

pam_pkcs11_la_SOURCES =  pam_pkcs11.c  \
			mapper_mgr.c mapper_mgr.h \
			pam_config.c pam_config.h
pam_pkcs11_la_LDFLAGS = -module -avoid-version
pam_pkcs11_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

install:       
	$(mkinstalldirs) $(DESTDIR)/lib/security
	$(libLTLIBRARIES_INSTALL) $(top_builddir)/src/pam_pkcs11/.libs/pam_pkcs11.so $(DESTDIR)/lib/security

format:
	indent *.c *.h
