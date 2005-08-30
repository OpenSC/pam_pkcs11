/*
 * PAM-PKCS11 Microsoft Universal Principal Name  mapper module
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

#define __MS_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/x509v3.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "ms_mapper.h"

/*
* This mapper uses (if available) the optional MS's Universal Principal Name 
* entry on the certificate to find user name.
* According with MS documentation, UPN has following structure:
* OID: 1.3.6.1.4.1.311.20.2.3
* UPN OtherName: user@domain.com
* UPN encoding:ASN1 UTF8
* 
* As UPN has in-built login and domain, No mapping file is used: login
* is implicit.
* A "checkdomain" flag is tested to compare domain if set.
* TODO: talk to Active Domain Service certificate an login validation
*/

static int ignorecase = 0;
static int ignoredomain =0;
static const char *domainname="";

/* check syntax and domain match on provided string */
static char *check_upn(char *str) {
	char *domain;
	if (!str) return NULL;
	if (!strchr(str,'@')) {
	    DBG1("'%s' is not a valid MS UPN",str);
	    return NULL;
	}
	domain=strchr(str,'@');
	*domain++='\0';
	if (!domain) {
	    DBG1("'%s' has not a valid MS UPN domain",str);
	    return NULL;
	}
	if (ignoredomain) return str;
	if (!strcmp(domainname,domain)) {
	    DBG2("Domain '%s' doesn't match UPN domain '%s'",domainname,domain);
	    return NULL;
	}
	return str;
}

static int compare_name(char *name, const char *user) {
  char *c_name= (ignorecase)?tolower_str(name):clone_str(name);
  char *c_user= (ignorecase)?tolower_str(user):clone_str(user);
  return !strcmp(c_name, c_user);
}

/*
* Extract the MS Universal Principal Name array list
*/
static char ** ms_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_UPN,NULL);
        if (!entries) {
                DBG("get_ms_upn() failed");
                return NULL;
        }
        return entries;
}

/*
parses the certificate and return the first valid UPN entry found, or NULL
*/
static char * ms_mapper_find_user(X509 *x509, void *context) {
	char *str;
        char **entries  = cert_info(x509,CERT_UPN,NULL);
        if (!entries) {
            DBG("get_ms_upn() failed");
            return NULL;
        }
	/* parse list until a valid string is found */
	for (str=*entries; str; str=*++entries) {
	     char *item,*res;
	     item = (ignorecase)?tolower_str(entries[0]):clone_str(entries[0]);
	     res= check_upn(item);
	     if (res) {
	        DBG2("Found valid UPN: '%s' maps to '%s' ",str,res);
		return clone_str(res);
	     } else {
		DBG1("Invalid UPN found '%s'",str);
	     }
	}
	DBG("No valid upn found");
	return NULL;
}

/*
* parses the certificate and try to macht any UPN in the certificate
* with provided user
*/
static int ms_mapper_match_user(X509 *x509, const char *user, void *context) {
        char *str;
        int match_found = 0;
        char **entries  = cert_info(x509,CERT_UPN,NULL);
        if (!entries) {
            DBG("get_ms_upn() failed");
            return -1;
        }
        /* parse list of uids until match */
        for (str=*entries; str && (match_found==0); str=*++entries) {
	    char *login; 
	    if (ignorecase) login= check_upn(tolower_str(str));
	    else            login= check_upn(clone_str(str));
	    if ( compare_name(login,user) ) {
		DBG2("Match found for entry '%s' & login '%s'",str,login);
		match_found=1;
	    } else {
		DBG1("Match failed for entry '%s'",str);
	    }
	    free(login);
        }
        return match_found;
}

_DEFAULT_MAPPER_END


static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = ms_mapper_find_entries;
	pt->finder = ms_mapper_find_user;
	pt->matcher = ms_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

/**
* init routine
* parse configuration block entry
*/
#ifndef MS_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * ms_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
	int debug = scconf_get_bool(blk,"debug",0);
	ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	ignoredomain = scconf_get_bool(blk,"ignoredomain",ignoredomain);
	domainname = scconf_get_str(blk,"domainname",domainname);
	set_debug_level(debug);
	pt = init_mapper_st(blk,mapper_name);
	if (pt) DBG4("MS PrincipalName mapper started. debug: %d, idomain: %d, icase: %d, domainname: '%s'",debug,ignoredomain,ignorecase,domainname);
	else DBG("MS PrincipalName mapper initialization failed");
	return pt;
}

