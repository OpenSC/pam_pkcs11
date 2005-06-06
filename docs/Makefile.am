# Process this file with automake to create Makefile.in

XSLTPROC = @XSLTPROC@
HTMLFILES = pam_pkcs11.html pam_pkcs11.css
XMLFILES = pam_pkcs11.xml pam_pkcs11.xsl

MAINTAINERCLEANFILES = pam_pkcs11.html

MANSRC = \
	pam_pkcs11.8 card_eventmgr.1 pklogin_finder.1 \
	pkcs11_eventmgr.1 pkcs11_inspect.1

man_MANS = $(MANSRC)
noinst_DATA = $(HTMLFILES)
EXTRA_DIST = $(MANSRC) $(XMLFILES) $(HTMLFILES) doxygen.conf \
	README.mappers README.autologin README.eventmgr 

STYLESHEET = pam_pkcs11.xsl

%.html: %.xml $(STYLESHEET)
if HAVE_DOCBOOK
	$(XSLTPROC) --path /usr/share/sgml/docbook/xsl-stylesheets/xhtml:/usr/share/xml/docbook/stylesheet/nwalsh/xhtml -o $@ $(STYLESHEET) $<
#tidy -im -utf8 -xml $@ || true
else
	@echo "Docbook support disabled, not building $@" >&2
endif

