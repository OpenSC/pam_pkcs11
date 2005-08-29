/*
 * PAM-PKCS11 mapping modules
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

#ifndef __MAPPERLIST_H_
#define __MAPPERLIST_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../mappers/mapper.h"

/*
* list of mappers that are statically linked
*/
typedef struct mapper_list_st {
	const char *name;
	struct mapper_module_st *data;
	int (*init)(scconf_block *blk, const char *mapper_name);
} mapper_list;

#ifndef __MAPPERLIST_C_
extern mapper_list static_mapper_list[];
#endif
	
/* End of mapperlist.h */
#endif
