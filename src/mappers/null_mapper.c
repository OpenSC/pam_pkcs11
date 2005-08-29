/*
 * PAM-PKCS11 NULL mapper module
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

#define __NULL_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/x509.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "mapper.h"
#include "null_mapper.h"

/*
* A blind mapper: just read from config default value
* and return it withouth further checking
*/

static const char *default_user = "nobody";
static int match=0;

static char * null_mapper_find_user(X509 *x509) {
	if ( !x509 ) return NULL;
	return (match)?clone_str((char *)default_user):NULL;
}

_DEFAULT_MAPPER_FIND_ENTRIES

_DEFAULT_MAPPER_MATCH_USER

_DEFAULT_MAPPER_END

#ifndef NULL_MAPPER_STATIC
struct mapper_module_st mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        mapper_module_data.name = name;
        mapper_module_data.block =blk;
        mapper_module_data.entries = mapper_find_entries;
        mapper_module_data.finder = null_mapper_find_user;
        mapper_module_data.matcher = mapper_match_user;
        mapper_module_data.mapper_module_end = mapper_module_end;
}

#else
struct mapper_module_st null_mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        null_mapper_module_data.name = name;
        null_mapper_module_data.block =blk;
        null_mapper_module_data.entries = mapper_find_entries;
        null_mapper_module_data.finder = null_mapper_find_user;
        null_mapper_module_data.matcher = mapper_match_user;
        null_mapper_module_data.mapper_module_end = mapper_module_end;
}
#endif

/**
* Initialize module
* returns 1 on success, 0 on error
*/
#ifndef NULL_MAPPER_STATIC
int mapper_module_init(scconf_block *ctx,const char *mapper_name) {
#else
int null_mapper_module_init(scconf_block *ctx,const char *mapper_name) {
#endif
	if (!ctx) return 0; /* should not occurs, but... */
	default_user = scconf_get_str( ctx,"default_user",default_user);
	match = scconf_get_bool( ctx,"default_match",0);
	init_mapper_st(ctx,mapper_name);
	DBG1("Null mapper match set to '%s'",match?"allways":"never");
	return 1;
}

