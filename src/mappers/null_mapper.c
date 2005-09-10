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
static int debug=0;

static char * mapper_find_user(X509 *x509,void *context) {
	if ( !x509 ) return NULL;
	return (match)?clone_str((char *)default_user):NULL;
}

/* not used */
#if 0
_DEFAULT_MAPPER_FIND_ENTRIES
#endif

_DEFAULT_MAPPER_MATCH_USER

_DEFAULT_MAPPER_END

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	/* pt->entries = mapper_find_entries; */ /* nothing to list */
	pt->entries = NULL;
	pt->finder = mapper_find_user;
	pt->matcher = mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

/**
* Initialize module
* returns 1 on success, 0 on error
*/
#ifndef NULL_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *ctx,const char *mapper_name) {
#else
mapper_module * null_mapper_module_init(scconf_block *ctx,const char *mapper_name) {
#endif
	mapper_module *pt= NULL;
	if (ctx) {
	default_user = scconf_get_str( ctx,"default_user",default_user);
	match = scconf_get_bool( ctx,"default_match",0);
		debug = scconf_get_bool( ctx,"debug",0);
	} else {
		DBG1("No block declaration for mapper '%'", mapper_name);
	}
	set_debug_level(debug);
	pt = init_mapper_st(ctx,mapper_name);
	if (pt) DBG1("Null mapper match set to '%s'",match?"allways":"never");
	else DBG("Null mapper initialization failed");
	return pt;
}

