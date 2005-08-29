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

#define __MAPPERLIST_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "mapperlist.h"

#include "subject_mapper.h"
#include "ldap_mapper.h"
#include "opensc_mapper.h"
#include "mail_mapper.h"
#include "ms_mapper.h"
#include "krb_mapper.h"
#include "digest_mapper.h"
#include "cn_mapper.h"
#include "uid_mapper.h"
#include "pwent_mapper.h"
#include "null_mapper.h"
#include "generic_mapper.h"
#include "openssh_mapper.h"

mapper_list static_mapper_list[] = {
#ifdef SUBJECT_MAPPER_STATIC
	{ "subject",subject_mapper_module_init,&subject_mapper_module_data },
#endif
#ifdef LDAP_MAPPER_STATIC
	{ "ldap",ldap_mapper_module_init,&ldap_mapper_module_data },
#endif
#ifdef OPENSC_MAPPER_STATIC
	{ "opensc",opensc_mapper_module_init,&opensc_mapper_module_data },
#endif
#ifdef MAIL_MAPPER_STATIC
	{ "mail",mail_mapper_module_init,&mail_mapper_module_data },
#endif
#ifdef MS_MAPPER_STATIC
	{ "ms",ms_mapper_module_init,&ms_mapper_module_data },
#endif
#ifdef KRB_MAPPER_STATIC
	{ "krb",krb_mapper_module_init,&krb_mapper_module_data },
#endif
#ifdef DIGEST_MAPPER_STATIC
	{ "digest",digest_mapper_module_init,&digest_mapper_module_data },
#endif
#ifdef CN_MAPPER_STATIC
	{ "cn",cn_mapper_module_init,&cn_mapper_module_data },
#endif
#ifdef UID_MAPPER_STATIC
	{ "uid",uid_mapper_module_init,&uid_mapper_module_data },
#endif
#ifdef PWENT_MAPPER_STATIC
	{ "pwent",pwent_mapper_module_init,&pwent_mapper_module_data },
#endif
#ifdef GENERIC_MAPPER_STATIC
	{ "generic",generic_mapper_module_init,&generic_mapper_module_data },
#endif
#ifdef OPENSSH_MAPPER_STATIC
	{ "openssh",openssh_mapper_module_init,&openssh_mapper_module_data },
#endif
#ifdef NULL_MAPPER_STATIC
	{ "null", null_mapper_module_init, &null_mapper_module_data },
#endif
	{ NULL, NULL, NULL }
};

/* End of mapperlist.c */
#undef __MAPPERLIST_C_
