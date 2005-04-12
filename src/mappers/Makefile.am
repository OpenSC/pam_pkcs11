# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

libdir = @libdir@/pam_pkcs11

AM_LDFLAGS = -module -avoid-version

COMMON_SOURCES = mapper.c mapper.h

lib_LTLIBRARIES = subject_mapper.la ldap_mapper.la opensc_mapper.la \
	mail_mapper.la ms_mapper.la krb_mapper.la digest_mapper.la \
	cn_mapper.la uid_mapper.la pwent_mapper.la null_mapper.la \
	generic_mapper.la

generic_mapper_la_SOURCES = $(COMMON_SOURCES) generic_mapper.c
generic_mapper_la_LIBADD = @LIBSCCONF@  @LIBCOMMON@

subject_mapper_la_SOURCES = $(COMMON_SOURCES) subject_mapper.c
subject_mapper_la_LIBADD = @LIBSCCONF@  @LIBCOMMON@

ldap_mapper_la_SOURCES = $(COMMON_SOURCES) ldap_mapper.c
ldap_mapper_la_LIBADD = @LIBSCCONF@

opensc_mapper_la_SOURCES = $(COMMON_SOURCES) opensc_mapper.c
opensc_mapper_la_LIBADD = @LIBSCCONF@

mail_mapper_la_SOURCES = $(COMMON_SOURCES) mail_mapper.c
mail_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

ms_mapper_la_SOURCES = $(COMMON_SOURCES) ms_mapper.c
ms_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

krb_mapper_la_SOURCES = $(COMMON_SOURCES) krb_mapper.c
krb_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

cn_mapper_la_SOURCES = $(COMMON_SOURCES) cn_mapper.c
cn_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

uid_mapper_la_SOURCES = $(COMMON_SOURCES) uid_mapper.c
uid_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

pwent_mapper_la_SOURCES = $(COMMON_SOURCES) pwent_mapper.c
pwent_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

digest_mapper_la_SOURCES = $(COMMON_SOURCES) digest_mapper.c
digest_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

null_mapper_la_SOURCES = $(COMMON_SOURCES) null_mapper.c
null_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@

