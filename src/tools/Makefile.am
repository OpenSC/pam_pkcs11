# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = $(PCSC_CFLAGS) $(CRYPTO_CFLAGS)
AM_LDFLAGS = $(PCSC_LIBS)

if HAVE_PCSC
bin_PROGRAMS = card_eventmgr pkcs11_eventmgr pklogin_finder pkcs11_inspect pkcs11_listcerts pkcs11_setup
card_eventmgr_SOURCES = card_eventmgr.c
card_eventmgr_LDADD = $(LIBSCCONF) $(LIBCOMMON)
else
bin_PROGRAMS = pkcs11_eventmgr pklogin_finder pkcs11_inspect pkcs11_listcerts pkcs11_setup
endif

pklogin_finder_SOURCES = pklogin_finder.c
pklogin_finder_LDADD = ../pam_pkcs11/libfinder.la $(LIBMAPPERS) 

pkcs11_listcerts_SOURCES = pkcs11_listcerts.c
pkcs11_listcerts_LDADD = ../pam_pkcs11/libfinder.la $(LIBSCCONF) $(LIBCOMMON) $(OPENSSL_LIBS)

pkcs11_eventmgr_SOURCES = pkcs11_eventmgr.c
pkcs11_eventmgr_LDADD = $(LIBSCCONF) $(LIBCOMMON) $(CRYPTO_LIBS)

pkcs11_inspect_SOURCES = pkcs11_inspect.c
pkcs11_inspect_LDADD = ../pam_pkcs11/libfinder.la $(LIBMAPPERS)

pkcs11_setup_SOURCES = pkcs11_setup.c
pkcs11_setup_LDADD = $(LIBSCCONF) $(LIBCOMMON)
