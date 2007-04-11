/*
 * PAM-PKCS11 Certificate digest mapper module
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

#define __DIGEST_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../common/cert_st.h"
#include "../common/alg_st.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "digest_mapper.h"
/*
* Create Certificate digest and use it to perform mapping process
*/

static const char *mapfile = "none";
static ALGORITHM_TYPE algorithm= ALGORITHM_SHA1;
static int debug= 0;

/*
* return fingerprint of certificate
*/
static char ** digest_mapper_find_entries(X509 *x509, void *context) {
	char **entries;
	if ( !x509 ) {
                DBG("NULL certificate provided");
		return NULL;
	}
	entries= cert_info(x509,CERT_DIGEST,algorithm);
	DBG1("entries() Found digest '%s'",entries[0]);
	return entries;
}

static char * digest_mapper_find_user(X509 *x509, void *context) {
	char **entries;
	if ( !x509 ) {
                DBG("NULL certificate provided");
		return NULL;
	}
	entries = cert_info(x509,CERT_DIGEST,algorithm);
	DBG1("find() Found digest '%s'",entries[0]);
        return mapfile_find(mapfile,entries[0],1);
}

/*
* parses the certificate and try to macth certificate digest
* with provided user
*/
static int digest_mapper_match_user(X509 *x509,const char *login, void *context) {
        char **entries;
        if (!x509) {
                DBG("NULL certificate provided");
                return 0;
        }
	entries = cert_info(x509,CERT_DIGEST,algorithm);
	DBG1("match() Found digest '%s'",entries[0]);
        return mapfile_match(mapfile,entries[0],login,1);
}

_DEFAULT_MAPPER_END

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = digest_mapper_find_entries;
	pt->finder = digest_mapper_find_user;
	pt->matcher = digest_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

/**
* Initialize module
* returns 1 on success, 0 on error
*/
#ifndef DIGEST_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * digest_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
	char *hash_alg_string;
	if (blk) { 
	debug = scconf_get_bool( blk,"debug",0);
	hash_alg_string = scconf_get_str( blk,"algorithm","sha1");
		mapfile= scconf_get_str(blk,"mapfile",mapfile);
	} else {
		/* should not occurs, but... */
		DBG1("No block declaration for mapper '%s'",mapper_name);
	}
	set_debug_level(debug);
	algorithm = Alg_get_alg_from_string(hash_alg_string);
	if(algorithm == ALGORITHM_NULL) {
		DBG1("Invalid digest algorithm %s, using 'sha1'", hash_alg_string);
		algorithm = ALGORITHM_SHA1;
	}
	pt = init_mapper_st(blk,mapper_name);
	if (pt) DBG3("Digest mapper started. debug: %d, mapfile: %s, algorithm: %s",debug,mapfile,hash_alg_string);
	else DBG("Digest mapper initialization failed");
	return pt;
}
