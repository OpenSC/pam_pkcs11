# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

TO_INSTALL = \
	subject_mapping.example \
	mail_mapping.example \
	digest_mapping.example \
	pkcs11_eventmgr.conf.example \
	card_eventmgr.conf.example

EXTRA_DIST = $(TO_INSTALL) \
	pam.d_ignore_no_card.example \
	pam.d_login.example.in \
	pam_pkcs11.conf.example.in

doc_DATA = $(TO_INSTALL) \
	pam_pkcs11.conf.example \
	pam.d_login.example \
	pam.d_ignore_no_card.example
