/*
 * PAM-PKCS11 ldap mapper module
 * Copyright (C) 2005 Dominik Fischer <dom_fischer@web.de>
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
 * pam-pkcs11 is copyright (C) 2003-2004 of Mario Strasser <mast@gmx.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * $Id$
 */

#define __LDAP_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ldap.h>
#include <openssl/x509.h>
#include "../scconf/scconf.h"
#include "../common/strings.h"
#include "../common/debug.h"
#include "mapper.h"
#include "ldap_mapper.h"

/*
* This mapper uses the "login" parameter from mapper_match_user and
* uses it to get a certificate from a LDAP server. The digest of
* this certificate is then compared to the digest of the certificate
* from smartcard.
* Configuration is done in pam_pkcs11.conf.
*/

/*
* TODO: Support for LDAPS Connection
*/

/*** Internal vars *****************************************************/

static const char *ldaphost="localhost";
static int ldapport=389;
static int scope=0; /* 0: LDAP_SCOPE_BASE, 1: LDAP_SCOPE_ONE, 2: LDAP_SCOPE_SUB */
static const char *binddn="";
static const char *passwd="";
static const char *base="ou=People,o=example,c=com";
static const char *attribute="userCertificate";
static const char *filter="(&(objectClass=posixAccount)(uid=%s)";
static int searchtimeout=20;
static int ignorecase=0;
static const X509 *ldap_x509;

/*** Internal funcs ****************************************************/

/**
* Get certificate from LDAP-Server.
*/
int ldap_get_certificate(const char *login)
{
	LDAP *ldap_connection;
	int ret, entries;
	LDAPMessage *res;
	LDAPMessage *entry;
	char **vals = NULL;
	struct berval **bvals = NULL;
	BerElement *ber = NULL;
	char *name = NULL;
	char filter_str[100];
	char *attrs[2];

	attrs[0] = (char *)attribute;
	attrs[1] = NULL;
	

	DBG("ldap_get_certificate(): begin");
	DBG1("ldap_get_certificate(): login = %s", login);

	snprintf(filter_str, sizeof(filter_str), filter, login); 

	DBG1("ldap_get_certificate(): filter_str = %s", filter_str);
	
	ldap_connection = ldap_init(ldaphost, ldapport);
	if ( NULL == ldap_connection) {
		DBG("ldap_init() failed");
		return(-1);
	}

	if ( 0 != ldap_simple_bind_s(ldap_connection, binddn, passwd)) {
		DBG("ldap_simple_bind_s() failed");
		return(-2);
	}

	if ( LDAP_SUCCESS != ldap_search_s(ldap_connection, base, LDAP_SCOPE_SUB, filter_str, attrs, 0, &res)) {
		DBG("ldap_search_s() failed");
		ldap_unbind_s(ldap_connection);
		return(-3);
	} else {
		entries = ldap_count_entries(ldap_connection, res);
		DBG1("ldap_get_certificate(): entries = %d", entries);

		/* Only first entry is used. "filter" and "attribute" should be choosen, so that only one entry with
		 * one attribute is returned */
		if ( NULL == (entry = ldap_first_entry(ldap_connection, res))){
			DBG("ldap_first_entry() failed");
			ldap_unbind_s(ldap_connection);
			return(-4);
		}

		/* Only first attribute is used. See comment above... */
		if ( NULL == (name = ldap_first_attribute(ldap_connection, res, &ber))){
			DBG("ldap_first_attribute() failed (rc=%d)");
			ldap_unbind_s(ldap_connection);
			return(-5);
		}
		DBG1("attribute name = %s", name);

		/* TODO: Add support for multi-value attribute for usercertificate */
		bvals = ldap_get_values_len(ldap_connection, entry, name);
		ldap_x509 = d2i_X509(NULL, (unsigned char **) &bvals[0]->bv_val, bvals[0]->bv_len);
		if (NULL == ldap_x509) {
			DBG("d2i_X509() failed");
			ldap_msgfree(res);
			ldap_unbind_s(ldap_connection);
			return(-6);
		}else {
			DBG("d2i_X509(): success");
		}
		ldap_msgfree(res);
	}
	if ( 0 != (ret = ldap_unbind_s(ldap_connection))) {
		DBG("ldap_unbind_s() failed.");
		ldap_perror(ldap_connection, "ldap_unbind_s() failed.");
		return(-1);
	};

	DBG("ldap_get_certificate(): end");
	return 1;
}

int read_config(scconf_block *blk)
{
	int debug = scconf_get_bool(blk,"debug",0);
	ldaphost = scconf_get_str(blk,"ldaphost",ldaphost);
	ldapport = scconf_get_int(blk,"ldapport",ldapport);
	scope = scconf_get_int(blk,"scope",scope);
	binddn = scconf_get_str(blk,"binddn",binddn);
	passwd = scconf_get_str(blk,"passwd",passwd);
	base = scconf_get_str(blk,"base",base);
	attribute = scconf_get_str(blk,"attribute",attribute);
	filter = scconf_get_str(blk,"filter",filter);
	ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	searchtimeout = scconf_get_int(blk,"searchtimeout",searchtimeout);

	set_debug_level(debug);

	DBG("LDAP mapper started.");
	DBG1("debug      = %d", debug);
	DBG1("ignorecase = %d", ignorecase);
	DBG1("ldaphost   = %s", ldaphost);
	DBG1("ldapport   = %d", ldapport);
	DBG1("scope      = %d", scope);
	DBG1("binddn     = %s", binddn);
	DBG1("passwd     = %s", passwd);
	DBG1("base       = %s", base);
	DBG1("attribute  = %s", attribute);
	DBG1("filter     = %s", filter);
	return 1;

}

_DEFAULT_MAPPER_END
_DEFAULT_MAPPER_FIND_ENTRIES
_DEFAULT_MAPPER_FIND_USER

static int mapper_match_user(X509 *x509, const char *login, void *context)
{
	char *str;
	int match_found = 0;
	char **digest;
	char **ldap_digest;
	EVP_PKEY *pubk;
	EVP_PKEY *ldap_pubk;

	if ( 1 != ldap_get_certificate(login)){
		DBG("ldap_get_certificate() failed");
		match_found = 0;
	} else {
		// TODO: maybe compare public keys instead of hashes
		if ( 0 == X509_cmp(x509, ldap_x509)) {
			DBG("Certifcates matching");
			match_found = 1;
		} else {
			DBG("Certifcates NOT matching");
			match_found = 0;
		}
	}
	return match_found;
}

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = mapper_find_entries;
	pt->finder = mapper_find_user;
	pt->matcher = mapper_match_user;
	pt->deinit = mapper_module_end;

	return pt;
}
#ifndef LDAP_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * ldap_mapper_module_init(scconf_block *blk,const char *mapper_name) {
	mapper_module *pt;

        pt = init_mapper_st(blk,mapper_name);

	if (blk) {
		read_config(blk);
	} else {
		set_debug_level(1);
		DBG1("No configuration entry for mapper '%s'. Assume defaults", mapper_name);
	}
	
        return pt;
}

