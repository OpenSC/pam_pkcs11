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

#define __SUBJECT_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*#include <openssl/objects.h> */
/*#include <openssl/err.h> */
#include "../common/cert_st.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "subject_mapper.h"

static const char *filename = "none";
static int ignorecase = 0;
static int debug = 0;

/*
* returns the Certificate subject
*/
static char ** subject_mapper_find_entries(X509 *x509, void *context) {
	char **entries= cert_info(x509,CERT_SUBJECT,ALGORITHM_NULL);
	if (!entries) {
		DBG("X509_get_subject_name failed");
		return NULL;
	}
	return entries;
}

/*
parses the certificate and return the first Subject entry found, or NULL
*/
static char * subject_mapper_find_user(X509 *x509, void *context, int *match) {
	char **entries = cert_info(x509,CERT_SUBJECT,ALGORITHM_NULL);
	if (!entries) {
		DBG("X509_get_subject_name failed");
		return NULL;
	}
	char* val = mapfile_find(filename,entries[0],ignorecase,match);
	if(entries[0]) {
		free(entries[0]);
	}
	return val;
}

/*
* parses the certificate and try to match Subject in the certificate
* with provided user
*/
static int subject_mapper_match_user(X509 *x509, const char *login, void *context) {
	char **entries = cert_info(x509,CERT_SUBJECT,ALGORITHM_NULL);
	if (!entries) {
		DBG("X509_get_subject_name failed");
		return -1;
	}
	return mapfile_match(filename,entries[0],login,ignorecase);
}

_DEFAULT_MAPPER_END


static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = subject_mapper_find_entries;
	pt->finder = subject_mapper_find_user;
	pt->matcher = subject_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}


/**
* Initialization routine
*/
#ifndef SUBJECT_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * subject_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
	if (blk) {
	debug      = scconf_get_bool(blk,"debug",0);
	filename   = scconf_get_str(blk,"mapfile",filename);
	ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	} else {
		DBG1("No block declaration for mapper '%s'",mapper_name);
	}
	set_debug_level(debug);
	pt= init_mapper_st(blk,mapper_name);
	if(pt) DBG3("Subject mapper started. debug: %d, mapfile: %s, icase: %d",debug,filename,ignorecase);
	else DBG("Subject mapper initialization failed");
        return pt;
}
