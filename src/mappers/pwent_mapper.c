/*
 * PAM-PKCS11 CN to passwd mapper module
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

#define __PWENT_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pwd.h>
#include <sys/types.h>
#include "../common/cert_st.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "pwent_mapper.h"

/*
* This mapper search the common name (CN) of the certificate in
* getpwent() passwd entries by trying to match login or gecos fields
*
* note: nss implementations use /etc/nsswitch.conf as indicator to
* where to retrieve pw entries ( see man 5 nsswitch.conf )
*/

static int ignorecase = 0;
static int debug = 0;

/*
* Returns the common name of certificate as an array list
*/
static char ** pwent_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_CN,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_common_name() failed");
                return NULL;
        }
        return entries;
}

/*
parses the certificate and return the _first_ CN entry found, or NULL
*/
static char * pwent_mapper_find_user(X509 *x509,void *context, int *match) {
        char *str;
	struct passwd *pw;
	char *found_user = NULL;
        char **entries  = cert_info(x509,CERT_CN,ALGORITHM_NULL);
        if (!entries) {
            DBG("get_common_name() failed");
            return NULL;
        }
	DBG1("trying to find pw_entry for cn '%s'", *entries);
	/* First: direct try to avoid long searchtime or massive network traffic
	 * for large amount of users in pw database.
	 * (Think of 10000 or more users, mobile connection to ldap, etc.) 
	 */
        for (str=*entries; str ; str=*++entries) {
		pw = getpwnam(str);
                if (pw == NULL) {
		    DBG1("Entry for %s not found (direct).", str);
                } else {
			DBG1("Found CN in pw database for user %s (direct).", str);
			*match = 1;
			return pw->pw_name;
		}
	}

	/* Second: search all entries (old behaviour) */
	/* parse list of uids until match */
	for (str=*entries; str ; str=*++entries) {
	    found_user= search_pw_entry((const char *)str,ignorecase);
            if (!found_user) {
                DBG1("CN entry '%s' not found in pw database. Trying next",str);
                continue;
            } else {
                DBG1("Found CN in pw database for user '%s'",found_user);
		*match = 1;
		/* WJG: Usually allocated mem is returned - memleak/problem? */
		return found_user;
	    }
        }
	DBG("No pw entry maps to any provided Common Name");
        return NULL;
}

/*
* parses the certificate and try to macht any CN in the certificate
* with provided user
* NOTE:
* Instead of parse any pwent entry, this routine perform a direct
* approach: obtain pw_entry for provided login, and compare against
* provided CN's. i'ts easier and faster
*/
static int pwent_mapper_match_user(X509 *x509, const char *login, void *context) {
        char *str;
	struct passwd *pw = getpwnam(login);
        char **entries  = cert_info(x509,CERT_CN,ALGORITHM_NULL);
        if (!entries) {
            DBG("get_common_name() failed");
            return -1;
        }
	if (!pw) {
	    DBG1("There are no pwentry for login '%s'",login);
	    return -1;
	}
        /* parse list of uids until match */
        for (str=*entries; str ; str=*++entries) {
            DBG1("Trying to match pw_entry for cn '%s'",str);
	    if (compare_pw_entry(str,pw,ignorecase)) {
		DBG2("CN '%s' Match login '%s'",str,login);
		return 1;
	    } else {
		DBG2("CN '%s' doesn't match login '%s'",str,login);
	        continue; /* try another entry. or perhaps return(0) ? */
	    }
        }
	DBG("Provided user doesn't match to any found Common Name");
        return 0;
}

_DEFAULT_MAPPER_END

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = pwent_mapper_find_entries;
	pt->finder = pwent_mapper_find_user;
	pt->matcher = pwent_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}


#ifndef PWENT_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * pwent_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
	if (blk) {
		debug= scconf_get_bool(blk,"debug",0);
	ignorecase= scconf_get_bool(blk,"ignorecase",ignorecase);
	} else {
		DBG1("No block declarartion for mapper '%s'",mapper_name);
	}
	set_debug_level(debug);
	pt = init_mapper_st(blk,mapper_name);
	if (pt) DBG("pwent mapper started");
	else DBG("pwent mapper initialization failed");
        return pt;
}

