/*
 * PAM-PKCS11 generic mapper skeleton
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

#define _GENERIC_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"

/*
* Skeleton for mapper modules
*/

static const char *mapfile = "none";
static int ignorecase = 0;

static char **generic_mapper_find_entries(X509 *x509) {
	return NULL;
}

static char *generic_mapper_find_user(X509 *x509) {
	char *entry,**entries;
	int n;
        if (!x509) {
                DBG("NULL certificate provided");
                return 0;
        }
	entries= mapper_find_entries(x509);
	if (!entries) {
		DBG("Cannot find any entries in certificate");
		return 0;
	}
	for (n=0;n<CERT_INFO_SIZE;n++) {
		char *res;
		entry=entries[n];
		if (!entry) {
			DBG("No more available entries");
			return NULL;
		}
		res = mapfile_find(mapfile,entry,ignorecase);
		if (!res ) {
			DBG1("No map for entry %s, trying next one",entry);
			continue;
		}
		DBG2("Entry '%s' maps to '%s' ",entry,res);
		return res;
	}
	/* arriving here means end of list reached */
	DBG("End of entries list reached");
	return NULL;
}

static int generic_mapper_match_user(X509 *x509, const char *login) {
	char *entry,**entries;
	int n;
        if (!x509) {
                DBG("NULL certificate provided");
                return 0;
        }
	if (!login || is_empty_str(login) ) {
		DBG("NULL login provided");
		return 0;
	}
	entries= mapper_find_entries(x509);
	if (!entries) {
		DBG("Cannot find any entries in certificate");
		return 0;
	}
	for (n=0;n<CERT_INFO_SIZE;n++) {
		int res;
		entry=entries[n];
		if (!entry) {
			DBG("No more available entries to match");
			return 0;
		}
		res = mapfile_match(mapfile,entry,login,ignorecase);
		if (res == 0 ) {
			DBG1("No match for entry '%s'. Trying next one",entry);
			continue;
		}
		if (res < 0 ) {
			DBG1("Error in matching process for entry %s",entry);
			return -1; /* or perhaps ignore and try next? */
		}
		DBG2("Match found for entry '%s' and login '%s'",entry,login);
		return 1;
	}
	/* arriving here means end of list reached */
	DBG("End of list reached");
	return 0;
}

_DEFAULT_MAPPER_END

struct mapper_module_st mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        mapper_module_data.name = name;
        mapper_module_data.block =blk;
        mapper_module_data.entries = generic_mapper_find_entries;
        mapper_module_data.finder = generic_mapper_find_user;
        mapper_module_data.matcher = generic_mapper_match_user;
        mapper_module_data.mapper_module_end = mapper_module_end;
}

/**
* Initialize module
* returns 1 on success, 0 on error
*/
int mapper_module_init(scconf_block *blk,const char *name) {
	int debug;
	if (!blk) return 0; /* should not occurs, but... */
	debug = scconf_get_bool( blk,"debug",0);
	set_debug_level(debug);
	ignorecase = scconf_get_bool( blk,"ignorecase",0);
	mapfile= scconf_get_str(blk,"mapfile",mapfile);
	init_mapper_st(blk,name);
	DBG3("Generic mapper started. debug: %d, mapfile: %s, ignorecase: %s",debug,mapfile,ignorecase);
	return 1;
}

