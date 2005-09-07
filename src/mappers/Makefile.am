# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

libdir = @libdir@/pam_pkcs11

# Add openssl specific flags
AM_CFLAGS = @OPENSSL_CFLAGS@

# Statically linked mapperis list
# Uncomment to get refered mapper statically linked
# DON'T FORGET update libmappers_la_SOURCES and lib_LTLIBRARIES entries below
#
AM_CFLAGS += -DSUBJECT_MAPPER_STATIC
#AM_CFLAGS += -DLDAP_MAPPER_STATIC
#AM_CFLAGS += -DOPENSC_MAPPER_STATIC
AM_CFLAGS += -DMAIL_MAPPER_STATIC
AM_CFLAGS += -DMS_MAPPER_STATIC
AM_CFLAGS += -DKRB_MAPPER_STATIC
AM_CFLAGS += -DDIGEST_MAPPER_STATIC
AM_CFLAGS += -DCN_MAPPER_STATIC
AM_CFLAGS += -DUID_MAPPER_STATIC
AM_CFLAGS += -DPWENT_MAPPER_STATIC
AM_CFLAGS += -DGENERIC_MAPPER_STATIC
#AM_CFLAGS += -DOPENSSH_MAPPER_STATIC
AM_CFLAGS += -DNULL_MAPPER_STATIC

# list of statically linked mappers
noinst_LTLIBRARIES = libmappers.la
libmappers_la_SOURCES = mapper.c mapper.h \
	subject_mapper.c subject_mapper.h \
	mail_mapper.c mail_mapper.h \
	ms_mapper.c ms_mapper.h \
	krb_mapper.c krb_mapper.h \
	digest_mapper.c digest_mapper.h \
	cn_mapper.c cn_mapper.h \
	uid_mapper.c uid_mapper.h \
	pwent_mapper.c pwent_mapper.h \
	generic_mapper.c generic_mapper.h \
	null_mapper.c null_mapper.h \
	mapperlist.c mapperlist.h

libmappers_la_LDFLAGS = @LIBSCCONF@ @LIBCOMMON@

# list of dynamic linked mappers
if HAVE_LDAP
lib_LTLIBRARIES = ldap_mapper.la opensc_mapper.la openssh_mapper.la
else
lib_LTLIBRARIES = opensc_mapper.la openssh_mapper.la
endif

openssh_mapper_la_SOURCES = openssh_mapper.c openssh_mapper.h
openssh_mapper_la_LDFLAGS = -module -avoid-version
openssh_mapper_la_LIBADD = libmappers.la

# generic_mapper_la_SOURCES = generic_mapper.c generic_mapper.h
# generic_mapper_la_LDFLAGS = -module -avoid-version
# generic_mapper_la_LIBADD = libmappers.la

# subject_mapper_la_SOURCES = subject_mapper.c subject_mapper.h
# subject_mapper_la_LDFLAGS = -module -avoid-version
# subject_mapper_la_LIBADD = libmappers.la

if HAVE_LDAP
ldap_mapper_la_SOURCES = ldap_mapper.c ldap_mapper.h
ldap_mapper_la_LDFLAGS = -module -avoid-version
ldap_mapper_la_LIBADD = libmappers.la
endif

opensc_mapper_la_SOURCES = opensc_mapper.c opensc_mapper.h
opensc_mapper_la_LDFLAGS = -module -avoid-version
opensc_mapper_la_LIBADD = libmappers.la

# mail_mapper_la_SOURCES = mail_mapper.c mail_mapper.h
# mail_mapper_la_LDFLAGS = -module -avoid-version
# mail_mapper_la_LIBADD = libmappers.la

# ms_mapper_la_SOURCES = ms_mapper.c ms_mapper.h
# ms_mapper_la_LDFLAGS = -module -avoid-version
# ms_mapper_la_LIBADD = libmappers.la

# krb_mapper_la_SOURCES = krb_mapper.c krb_mapper.h
# krb_mapper_la_LDFLAGS = -module -avoid-version
# krb_mapper_la_LIBADD = libmappers.la

# cn_mapper_la_SOURCES = cn_mapper.c cn_mapper.h
# cn_mapper_la_LDFLAGS = -module -avoid-version
# cn_mapper_la_LIBADD = libmappers.la

# uid_mapper_la_SOURCES = uid_mapper.c uid_mapper.h
# uid_mapper_la_LDFLAGS = -module -avoid-version
# uid_mapper_la_LIBADD = libmappers.la

# pwent_mapper_la_SOURCES = pwent_mapper.c pwent_mapper.h
# pwent_mapper_la_LDFLAGS = -module -avoid-version
# pwent_mapper_la_LIBADD = libmappers.la

# digest_mapper_la_SOURCES = digest_mapper.c digest_mapper.h
# digest_mapper_la_LDFLAGS = -module -avoid-version
# digest_mapper_la_LIBADD = libmappers.la

# null_mapper_la_SOURCES = null_mapper.c null_mapper.h
# null_mapper_la_LDFLAGS = -module -avoid-version
# null_mapper_la_LIBADD = libmappers.la

