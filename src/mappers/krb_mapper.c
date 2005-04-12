/*
 * PAM-PKCS11 Kerberos Principal Name  mapper module
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

#define _KRB_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/x509v3.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"

/*
* This mapper uses (if available) the optional Kerberos Principal Name 
* entry on the certificate to find user name.
*/

/*
TODO:
Implement kerberos authentication via PKINIT protocol
*/

/*
* get Kerberos principal name of certificate
*/
/**
* Return array of found CN's
*/
static char ** krb_mapper_find_entries(X509 *x509) {
        char **entries= cert_info(x509,CERT_KPN,NULL);
        if (!entries) {
                DBG("get_krb_principalname() failed");
                return NULL;
        }
        return entries;
}
/*
parses the certificate and return the email entry found, or NULL
*/
static char * krb_mapper_find_user(X509 *x509) {
        char *res;
        char **entries= cert_info(x509,CERT_KPN,NULL);
        if (!entries) {
            DBG("get_krb_principalname() failed");
            return NULL;
        }
        DBG1("trying to map kpn entry '%s'",entries[0]);
        res = mapfile_find("none",entries[0],0);
        if (!res) {
            DBG("Error in map process");
            return NULL;
        }
        return clone_str(res);
}

/*
* parses the certificate and try to macht any CN in the certificate
* with provided user
*/
static int krb_mapper_match_user(X509 *x509, const char *login) {
	char *str;
        int match_found = 0;
        char **entries  = cert_info(x509,CERT_KPN,NULL);
        if (!entries) {
            DBG("get_krb_principalname() failed");
            return -1;
        }
        /* parse list of entries until match */
        for (str=*entries; str && (match_found==0); str=*++entries) {
            int res=0;
            DBG1("trying to map & match KPN entry '%s'",str);
            res = mapfile_match("none",str,login,0);
            if (!res) {
                DBG("Error in map&match process");
                return -1; /* or perhaps should be "continue" ??*/
            }
            if (res>0) match_found=1;
        }
        return match_found;
}

_DEFAULT_MAPPER_END

struct mapper_module_st mapper_module_data;

static void init_mapper_st(scconf_block *blk, const char *name) {
        mapper_module_data.name = name;
        mapper_module_data.block =blk;
        mapper_module_data.entries = krb_mapper_find_entries;
        mapper_module_data.finder = krb_mapper_find_user;
        mapper_module_data.matcher = krb_mapper_match_user;
        mapper_module_data.mapper_module_end = mapper_module_end;
}

/**
* init routine
* parse configuration block entry
*/
int mapper_module_init(scconf_block *blk,const char *mapper_name) {
	int debug = scconf_get_bool(blk,"debug",0);
	set_debug_level(debug);
	init_mapper_st(blk,mapper_name);
	return 1;
}

