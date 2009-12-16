# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in $(HTMLFILES) api/*
DISTCLEANFILES = doxygen.conf

XSLTPROC = @XSLTPROC@
HTMLFILES = pam_pkcs11.html mappers_api.html
XMLFILES = pam_pkcs11.xml mappers_api.xml \
	pam_pkcs11.xsl export-wiki.xsl \
	pam_pkcs11.css

MANSRC = \
	pam_pkcs11.8 card_eventmgr.1 pklogin_finder.1 \
	pkcs11_eventmgr.1 pkcs11_inspect.1

man_MANS = $(MANSRC)
noinst_DATA = $(HTMLFILES) doxygen.conf
EXTRA_DIST = $(MANSRC) $(XMLFILES) $(HTMLFILES) doxygen.conf.in \
	README.mappers README.autologin README.eventmgr \
	README.ldap_mapper export-wiki.sh generate-api.sh \
	api/index.html $(shell ls api/*)

STYLESHEET = pam_pkcs11.xsl

%.html: %.xml $(STYLESHEET)
if HAVE_DOCBOOK
	$(XSLTPROC) --path /usr/share/sgml/docbook/xsl-stylesheets/xhtml:/usr/share/xml/docbook/stylesheet/nwalsh/xhtml \
	--stringparam  section.autolabel 1 \
	--stringparam  section.label.includes.component.label 1 \
	-o $@ $(STYLESHEET) $<
#tidy -im -utf8 -xml $@ || true
else
	@echo "Docbook support disabled, not building $@" >&2
endif

api/index.html: doxygen.conf
	sh $(srcdir)/generate-api.sh $(srcdir)
