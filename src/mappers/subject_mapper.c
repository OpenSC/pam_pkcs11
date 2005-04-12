/*
 * PAM-PKCS11 Cert Subject to login file based mapper module
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

#define _SUBJECT_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"

static const char *filename = "none";
static int ignorecase = 0;

/*
* returns the Certificate subject
*/
static char ** subject_mapper_find_entries(X509 *x509) {
	char **entries= cert_info(x509,CERT_SUBJECT,NULL);
	if (!entries) {
		DBG("X509_get_subject_name failed");
		return NULL;
	}
	return entries;
}

/*
parses the certificate and return the first Subject entry found, or NULL
*/
static char * subject_mapper_find_user(X509 *x509) {
	char **entries = cert_info(x509,CERT_SUBJECT,NULL);
	if (!entries) {
		DBG("X509_get_subject_name failed");
		return NULL;
	}
	return mapfile_find(filename,entries[0],ignorecase);
}

/*
* parses the certificate and try to macth Subject in the certificate
* with provided user
*/
static int subject_mapper_match_user(X509 *x509, const char *login) {
	char **entries = cert_info(x509,CERT_SUBJECT,NULL);
	if (!entries) {
		DBG("X509_get_subject_name failed");
		return -1;
	}
	return mapfile_match(filename,entries[0],login,ignorecase);
}

_DEFAULT_MAPPER_END

struct mapper_module_st mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        mapper_module_data.name=name;
        mapper_module_data.block =blk;
        mapper_module_data.entries = subject_mapper_find_entries;
        mapper_module_data.finder = subject_mapper_find_user;
        mapper_module_data.matcher = subject_mapper_match_user;
        mapper_module_data.mapper_module_end = mapper_module_end;
}

/**
* Initialization routine
*/
int mapper_module_init(scconf_block *blk,const char *mapper_name) {
	int debug;
	if (!blk) return 0; /* should not occurs, but... */
	debug      = scconf_get_bool(blk,"debug",0);
	filename   = scconf_get_str(blk,"mapfile",filename);
	ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	set_debug_level(debug);
	init_mapper_st(blk,mapper_name);
	DBG3("Subject mapper started. debug: %d, mapfile: %s, icase: %d",debug,filename,ignorecase);
        return 1;
}
