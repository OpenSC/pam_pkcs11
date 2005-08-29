/*
 * PAM-PKCS11 DIR mapper module
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

#define __LDAP_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/x509.h>
#include "../scconf/scconf.h"
#include "../common/strings.h"
#include "mapper.h"
#include "ldap_mapper.h"

/*
* This mapper uses a LDAP entry to compare entries on the certificate
* with mapped fields in ldap server
* Certificate entry to ldap name map is done by mean of a mapping file
*/

#ifndef LDAP_MAPPER_STATIC
struct mapper_module_st mapper_module_data;
#else
struct mapper_module_st ldap_mapper_module_data;
#endif

_DEFAULT_MAPPER_END
_DEFAULT_MAPPER_FIND_ENTRIES
_DEFAULT_MAPPER_FIND_USER
_DEFAULT_MAPPER_MATCH_USER

#ifndef LDAP_MAPPER_STATIC
_DEFAULT_MAPPER_INIT
#else
int ldap_mapper_module_init(scconf_block *blk,const char *name) {
        ldap_mapper_module_data.name = name;
        ldap_mapper_module_data.block = blk;
        ldap_mapper_module_data.entries = mapper_find_entries;
        ldap_mapper_module_data.finder = mapper_find_user;
        ldap_mapper_module_data.matcher = mapper_match_user;
        ldap_mapper_module_data.mapper_module_end= mapper_module_end;
        return 1;
}
#endif

