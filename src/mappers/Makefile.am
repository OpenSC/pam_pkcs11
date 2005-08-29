# Process this file with automake to create Makefile.in

libdir = @libdir@/pam_pkcs11

# list of statically linked mappers
noinst_LTLIBRARIES = libmappers.la
libmappers_la_SOURCES = mapper.c mapper.h mapperlist.c mapperlist.h

AM_CFLAGS = @OPENSSL_CFLAGS@

# list of dynamic linked mappers
lib_LTLIBRARIES = subject_mapper.la ldap_mapper.la opensc_mapper.la \
	mail_mapper.la ms_mapper.la krb_mapper.la digest_mapper.la \
	cn_mapper.la uid_mapper.la pwent_mapper.la null_mapper.la \
	generic_mapper.la openssh_mapper.la

openssh_mapper_la_SOURCES = openssh_mapper.c
openssh_mapper_la_LDFLAGS = -module -avoid-version
openssh_mapper_la_LIBADD = @LIBSCCONF@  @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

generic_mapper_la_SOURCES = generic_mapper.c
generic_mapper_la_LDFLAGS = -module -avoid-version
generic_mapper_la_LIBADD = @LIBSCCONF@  @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

subject_mapper_la_SOURCES = subject_mapper.c
subject_mapper_la_LDFLAGS = -module -avoid-version
subject_mapper_la_LIBADD = @LIBSCCONF@  @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

ldap_mapper_la_SOURCES = ldap_mapper.c
ldap_mapper_la_LDFLAGS = -module -avoid-version
ldap_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

opensc_mapper_la_SOURCES = opensc_mapper.c
opensc_mapper_la_LDFLAGS = -module -avoid-version
opensc_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

mail_mapper_la_SOURCES = mail_mapper.c
mail_mapper_la_LDFLAGS = -module -avoid-version
mail_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

ms_mapper_la_SOURCES = ms_mapper.c
ms_mapper_la_LDFLAGS = -module -avoid-version
ms_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

krb_mapper_la_SOURCES = krb_mapper.c
krb_mapper_la_LDFLAGS = -module -avoid-version
krb_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

cn_mapper_la_SOURCES = cn_mapper.c
cn_mapper_la_LDFLAGS = -module -avoid-version
cn_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

uid_mapper_la_SOURCES = uid_mapper.c
uid_mapper_la_LDFLAGS = -module -avoid-version
uid_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

pwent_mapper.la: libmappers.la
pwent_mapper_la_SOURCES = pwent_mapper.c
pwent_mapper_la_LDFLAGS = -module -avoid-version
pwent_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

digest_mapper.la: libmappers.la
digest_mapper_la_SOURCES = digest_mapper.c
digest_mapper_la_LDFLAGS = -module -avoid-version
digest_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

null_mapper.la: libmappers.la
null_mapper_la_SOURCES = null_mapper.c
null_mapper_la_LDFLAGS = -module -avoid-version
null_mapper_la_LIBADD = @LIBSCCONF@ @LIBCOMMON@ libmappers.la @OPENSSL_LIBS@

