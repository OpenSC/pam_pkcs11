# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

FINDER_OBJS =  ../pam_pkcs11/mapper_mgr.o ../pam_pkcs11/pam_config.o

INCLUDES = @PCSC_CFLAGS@
AM_LDFLAGS = @PCSC_LIBS@
bin_PROGRAMS = card_eventmgr pkcs11_eventmgr pklogin_finder pkcs11_inspect

card_eventmgr_SOURCES = card_eventmgr.c
card_eventmgr_LDADD = @LIBSCCONF@ @LIBCOMMON@

pklogin_finder_SOURCES = pklogin_finder.c
pklogin_finder_LDADD = $(FINDER_OBJS) @LIBSCCONF@ @LIBCOMMON@

pkcs11_eventmgr_SOURCES = pkcs11_eventmgr.c
pkcs11_eventmgr_LDADD = @LIBSCCONF@ @LIBCOMMON@

pkcs11_inspect_SOURCES = pkcs11_inspect.c
pkcs11_inspect_LDADD = $(FINDER_OBJS) @LIBSCCONF@ @LIBCOMMON@
