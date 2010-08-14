/*
 * PAM-PKCS11 UID mapper module
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

#define __UID_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../common/cert_st.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "uid_mapper.h"

/*
* This mapper uses the Unique ID (UID) entry on the certificate to
* find user name.
*/

static const char *mapfile = "none";
static int ignorecase = 0;
static int debug = 0;

/**
* Return the list of UID's on this certificate
*/
static char ** uid_mapper_find_entries(X509 *x509, void *context) {
	char **entries= cert_info(x509,CERT_UID,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_unique_id() failed");
                return NULL;
        }

        return entries;
}

/*
parses the certificate and return the map of the first UID entry found
If no UID found or map error, return NULL
*/
static char * uid_mapper_find_user(X509 *x509, void *context, int *match) {
	char *res;
	char **entries= cert_info(x509,CERT_UID,ALGORITHM_NULL);
        if (!entries) {
            DBG("get_unique_id() failed");
            return NULL;
        }
        DBG1("trying to map uid entry '%s'",entries[0]);
        res = mapfile_find(mapfile,entries[0],ignorecase,match);
	if (!res) {
	    DBG("Error in map process");
	    return NULL;
	}
	return clone_str(res);
}

/*
* parses the certificate and try to macht any UID in the certificate
* with provided user
*/
static int uid_mapper_match_user(X509 *x509, const char *login, void *context) {
	char *str;
	int match_found = 0;
	char **entries  = cert_info(x509,CERT_UID,ALGORITHM_NULL);
        if (!entries) {
            DBG("get_unique_id() failed");
            return -1;
        }
	/* parse list of uids until match */
	for (str=*entries; str && (match_found==0); str=*++entries) {
	    int res=0;
            DBG1("trying to map & match uid entry '%s'",str);
            res = mapfile_match(mapfile,str,login,ignorecase);
	    if (!res) {
	        DBG("Error in map&match process");
	        return -1; /* or perhaps should be "continue" ??*/
	    }
	    if (res>0) match_found=1;
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
	pt->entries = uid_mapper_find_entries;
	pt->finder = uid_mapper_find_user;
	pt->matcher = uid_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}


#ifndef UID_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * uid_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
        if (blk) {
		debug= scconf_get_bool(blk,"debug",0);
	mapfile = scconf_get_str(blk,"mapfile",mapfile);
        ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	} else {
		DBG1("No block declaration for mapper '%'", mapper_name);
	}
        set_debug_level(debug);
	pt= init_mapper_st(blk,mapper_name);
        if(pt) DBG3("UniqueID mapper started. debug: %d, mapfile: %s, icase: %d",debug,mapfile,ignorecase);
	else DBG("UniqueID mapper initialization failed");
        return pt;
}

