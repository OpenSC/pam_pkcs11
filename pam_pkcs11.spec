Name:           pam_pkcs11
Version:        0.6.13
Release:        1%{?dist}
Summary:        PKCS #11 PAM module

Group:          System Environment/Base
License:        LGPL
URL:            https://github.com/OpenSC/pam_pkcs11
Source0:        https://github.com/OpenSC/pam_pkcs11/archive/refs/tags/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  pam-devel, openssl-devel
%{?_with_ldap:BuildRequires: openldap-devel}
%{?_with_curl:BuildRequires: curl-devel}
BuildRequires: libxslt libtool gettext docbook-style-xsl
BuildRequires: automake >= 1.7.8
Provides:      pam_pkcs11 = %{version}-%{release}

%description
This Linux-PAM module allows a X.509 certificate based user
authentication. The certificate and its dedicated private key are thereby
accessed by means of an appropriate PKCS #11 module. For the
verification of the users' certificates, locally stored CA
certificates as well as either online or locally accessible CRLs are
used.
Adittional included pam_pkcs11 related tools
- pkcs11_eventmgr: Generate actions on card insert/removal/timeout events
- pklogin_finder: Get the loginname that maps to a certificate
- pkcs11_inspect: Inspect the contents of a certificate
- make_hash_links: create hash link directories for storing CA's and CRL's

%package pcsc
Group:          System Environment/Utilities
Summary:        PCSC-Lite extra tools for pam_pkcs11
BuildRequires:  pcsc-lite-devel
Requires: pcsc-lite
Requires: pam_pkcs11
Provides: pam_pkcs11-pcsc = %{version}-%{release}

%description pcsc
This package contains pam_pkcs11 tools that relies on PCSC-Lite library
- card_eventmgr: Generate card insert/removal events

%package ldap
Group:          System Environment/Utilities
Summary:        LDAP Cert-to-Login mapper for pam_pkcs11
BuildRequires:  openldap-devel
Requires: openldap
Requires: pam_pkcs11
Provides: pam_pkcs11-ldap = %{version}-%{release}

%description ldap
This package contains a Certificate-To-Login mapper based on queries
to a LDAP server. As it depends on extra libraries, is distributed
as a separate package

- ldap_mapper.so: ldap based mapper library

%prep
%setup -q -n %{name}-%{name}-%{version}
./bootstrap

%build
%configure --disable-dependency-tracking %{?_with_curl} %{?_with_ldap}
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT/%{_libdir}/security/*.*a
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/*.*a

# Hardcoded defaults... no sysconfdir
install -dm 755 $RPM_BUILD_ROOT/etc/%{name}/cacerts
install -dm 755 $RPM_BUILD_ROOT/etc/%{name}/crls
install -m 644 etc/%{name}.conf.example $RPM_BUILD_ROOT/etc/%{name}/%{name}.conf
install -m 644 etc/card_eventmgr.conf.example $RPM_BUILD_ROOT/etc/%{name}/card_eventmgr.conf
install -m 644 etc/pkcs11_eventmgr.conf.example $RPM_BUILD_ROOT/etc/%{name}/pkcs11_eventmgr.conf

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING README TODO ChangeLog NEWS
%doc doc/pam_pkcs11.html
%doc doc/mappers_api.html
%doc doc/README.autologin
%doc doc/README.mappers
%config(noreplace) %{_sysconfdir}/%{name}/cacerts
%config(noreplace) %{_sysconfdir}/%{name}/crls
%config(noreplace) %{_sysconfdir}/%{name}/pam_pkcs11.conf
%config(noreplace) %{_sysconfdir}/%{name}/pkcs11_eventmgr.conf
%{_bindir}/pkcs11_make_hash_link
%{_bindir}/pkcs11_eventmgr
%{_bindir}/pklogin_finder
%{_bindir}/pkcs11_inspect
%{_bindir}/pkcs11_listcerts
%{_bindir}/pkcs11_setup
%{_libdir}/%{name}/openssh_mapper.so
%{_libdir}/%{name}/opensc_mapper.so
%{_libdir}/security/pam_pkcs11.so
%{_mandir}/man8/%{name}.8.gz
%{_mandir}/man1/pkcs11_eventmgr.1.gz
%{_mandir}/man1/pkcs11_inspect.1.gz
%{_mandir}/man1/pklogin_finder.1.gz
%{_mandir}/man1/pkcs11_listcerts.1.gz
%{_mandir}/man1/pkcs11_make_hash_link.1.gz
%{_mandir}/man1/pkcs11_setup.1.gz
%{_docdir}/%{name}/%{name}.conf.example
%{_docdir}/%{name}/pam.d_login.example
%{_docdir}/%{name}/subject_mapping.example
%{_docdir}/%{name}/mail_mapping.example
%{_docdir}/%{name}/digest_mapping.example
%{_docdir}/%{name}/pkcs11_eventmgr.conf.example
%{_docdir}/%{name}/pam.d_ignore_no_card.example
%{_datadir}/locale/*/LC_MESSAGES/*
%{_libdir}/systemd/system/pkcs11-eventmgr.service

%files pcsc
%config(noreplace) %{_sysconfdir}/%{name}/card_eventmgr.conf
%{_bindir}/card_eventmgr
%{_mandir}/man1/card_eventmgr.1.gz
%{_docdir}/%{name}/card_eventmgr.conf.example
%doc doc/README.eventmgr

%files ldap
%{_libdir}/%{name}/ldap_mapper.so
%doc doc/README.ldap_mapper

%changelog
* Wed Dec 28 2022 Etienne Barbier <etienne.barbier@atos.net> 0.6.12-1
- Update to 0.6.12

* Wed Jun 6 2007 Ludovic Rousseau <ludovic.rousseau@free.fr> 0:0.6.0-1
- Update to 0.6.0

* Wed Sep 7 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.5.3-2
- Add ldap_mapper.so as separate package, as it depends on external library
- Changes from FC4 team

* Thu Sep 1 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.5.3-0
- Update to 0.5.3
- Remove tools package, and create pcsc one with pcsc-lite dependent files

* Mon Apr 11 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.5.2-1
- Changed package name to pam_pkcs11

* Fri Apr 8 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.5.2-0
- Updated to 0.5.2 release
- Changed /etc/pkcs11 for /etc/pam_pkcs11
- Changed /usr/share/pkcs11_login for /usr/share/pam_pkcs11
- Next item is change package name to pam_pkcs11

* Thu Apr 7 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.5.1-0
- patches to avoid autotools in compile from tgz

* Tue Mar 29 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.5-1
- upgrade to 0.5beta1 version
- BuildRequires now complains compilation of html manual from xml file

* Mon Feb 28 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.4.4-2
- New pkcs11_eventmgr app in "tools" package

* Thu Feb 24 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.4.4-1
- Fix pcsc-lite dependencies

* Tue Feb 15 2005 Juan Antonio Martinez <jonsito@teleline.es> 0:0.4.4-0
- Update to 0.4.4b2

* Sun Sep 12 2004 Ville Skyttä <ville.skytta@iki.fi> - 0:0.3b-0.fdr.1
- Update to 0.3b.
- Disable dependency tracking to speed up the build.

* Tue May 4 2004 Ville Skyttä <ville.skytta@iki.fi> - 0:0.3-0.fdr.1
- Update to 0.3.
- Do not use libcurl by default; rebuild using "--with curl" to use it.

* Mon Mar 29 2004 Ville Skyttä <ville.skytta@iki.fi> - 0:0.2-0.fdr.1
- Update to 0.2.
- Use libcurl by default; rebuild using "--without curl" to disable.

* Wed Jan 21 2004 Ville Skyttä <ville.skytta@iki.fi> - 0:0.1-0.fdr.0.2.beta5
- Add the user_mapping config file.

* Mon Jan 19 2004 Ville Skyttä <ville.skytta@iki.fi> - 0:0.1-0.fdr.0.1.beta5
- First build.
