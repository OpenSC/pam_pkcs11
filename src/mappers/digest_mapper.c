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

#include <openssl/evp.h>
#include <openssl/x509.h>
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
static const char *algorithm= "sha1";

/*
* return fingerprint of certificate
*/
static char ** digest_mapper_find_entries(X509 *x509) {
	char **entries;
	if ( !x509 ) {
                DBG("NULL certificate provided");
		return NULL;
	}
	entries= cert_info(x509,CERT_DIGEST,algorithm);
	DBG1("entries() Found digest '%s'",entries[0]);
	return entries;
}

static char * digest_mapper_find_user(X509 *x509) {
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
static int digest_mapper_match_user(X509 *x509,const char *login) {
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

#ifndef DIGEST_MAPPER_STATIC
struct mapper_module_st mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        mapper_module_data.name = name;
        mapper_module_data.block =blk;
        mapper_module_data.entries = digest_mapper_find_entries;
        mapper_module_data.finder = digest_mapper_find_user;
        mapper_module_data.matcher = digest_mapper_match_user;
        mapper_module_data.mapper_module_end = mapper_module_end;
}

#else
struct mapper_module_st digest_mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        digest_mapper_module_data.name = name;
        digest_mapper_module_data.block =blk;
        digest_mapper_module_data.entries = digest_mapper_find_entries;
        digest_mapper_module_data.finder = digest_mapper_find_user;
        digest_mapper_module_data.matcher = digest_mapper_match_user;
        digest_mapper_module_data.mapper_module_end = mapper_module_end;
}
#endif

/**
* Initialize module
* returns 1 on success, 0 on error
*/
#ifndef DIGEST_MAPPER_STATIC
int mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
int digest_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	int debug;
	const EVP_MD *digest;
	if (!blk) return 0; /* should not occurs, but... */
	debug = scconf_get_bool( blk,"debug",0);
	algorithm = scconf_get_str( blk,"algorithm","sha1");
	set_debug_level(debug);
	digest = EVP_get_digestbyname(algorithm);
	if(!digest) {
		DBG1("Invalid digest algorithm %s, using 'sha1'",algorithm);
		algorithm="sha1";
	}
	mapfile= scconf_get_str(blk,"mapfile",mapfile);
	init_mapper_st(blk,mapper_name);
	DBG3("Digest mapper started. debug: %d, mapfile: %s, algorithm: %s",debug,mapfile,algorithm);
	return 1;
}
