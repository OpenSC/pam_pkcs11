/*
 * PAM-PKCS11 mail mapper module
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

#define __MAIL_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "mail_mapper.h"

/*
* This mapper uses (if available) the optional email entry on the certificate
* to find user name.
*/

/* where to retrieve aliases file ( email -> login pairs ) */
static const char *mapfile = "none";

/* ignore upper/lowercase in email comparisions */
static int ignorecase = 1;

/* also check the domain part on email field */
static int ignoredomain = 1;
static char *hostname = NULL;

static int debug=0;

/*
* Extract list of email entries on certificate
*/
static char ** mail_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_EMAIL,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_email() failed");
                return NULL;
        }
        return entries;
}

/**
* check mail domain name against hostname
* returns  match ignoredomain
*	   false false		-> 0
*	   false true		-> 1
*	   true  false		-> 1
*	   true  true		-> 1
*/
static int check_domain(char *domain) {
	if (ignoredomain) return 1;	     /* no domain check */
	if (strlen(hostname)==0) return 1; /* empty domain */
	if (!domain) return 0;
	if ( strstr(hostname,domain) ) return 1;
	return 0;
}

/**
* compare previously mapped email against user name
*/
static int compare_email(char *email, const char *user) {
  char *c_email,*c_user;
  char *at;
  c_email= (ignorecase)?tolower_str(email):clone_str(email);
  c_user= (ignorecase)?tolower_str(user):clone_str(user);
  /* test if full login@mail.domain emailname is provided */
  at = strchr(c_email, '@');
  if (at != NULL) {/* domain provided: check ignoredomain flag*/
    int flag= check_domain(1+at);
    if (!flag) {
	DBG2("Mail domain name %s does not match with %s",1+at,hostname);
	return 0;
    }
    return (at - c_email) == strlen(c_user) && !strncmp(c_email, c_user, strlen(c_user));
  } else { /* no domain provide: just a strcmp */
    return !strcmp(c_email, c_user);
  }
}

/*
parses the certificate and return the email entry found, or NULL
*/
static char * mail_mapper_find_user(X509 *x509, void *context, int *match) {
        char **entries= cert_info(x509,CERT_EMAIL,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_email() failed");
                return NULL;
        }
	/* TODO: What's on ignoredomain flag ?*/
	return mapfile_find(mapfile,entries[0],ignorecase,match);
}

/*
* parses the certificate and try to macht any Email in the certificate
* with provided user
*/
static int mail_mapper_match_user(X509 *x509, const char *login, void *context) {
	int match = 0;
	char *item;
	char *str;
        char **entries= cert_info(x509,CERT_EMAIL,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_email() failed");
                return 0;
        }
	DBG1("Trying to find match for user '%s'",login);
	for (item=*entries;item;item=*++entries) {
	    DBG1("Trying to match email entry '%s'",item);
	    str= mapfile_find(mapfile,item,ignorecase,&match);
	    if (!str) {
		DBG("Mapping process failed");
		return -1; /* TODO: perhaps should try to continue... */
	    }
	    if(compare_email(str,login)) {
		DBG2("Found match from '%s' to '%s'",item,login);
		return 1;
	    }
	}
	/* arriving here means no match */
	DBG1("Cannot match any found email to '%s'",login);
	return 0;
}

_DEFAULT_MAPPER_END


static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = mail_mapper_find_entries;
	pt->finder = mail_mapper_find_user;
	pt->matcher = mail_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

/**
* init routine
* parse configuration block entry
*/
#ifndef MAIL_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * mail_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
	if (blk) {
		debug = scconf_get_bool(blk,"debug",0);
	ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	ignoredomain = scconf_get_bool(blk,"ignoredomain",ignoredomain);
	mapfile = scconf_get_str(blk,"mapfile",mapfile);
	} else {
		DBG1("No block declaration for mapper '%s'",mapper_name);
	}
	set_debug_level(debug);
	/* obtain and store hostname */
	/* Note: in some systems without nis/yp, getdomainname() call
	   returns NULL. So instead we use gethostname() an match
	   mail domain by mean strstr() funtion */
        if (!ignoredomain) {
		hostname= calloc(256,sizeof(char));
		if (!hostname) {
		    DBG("Calloc for hostname failed");
		} else {
		    gethostname(hostname,255);
		    *(hostname+255)='\0';
		    DBG1("Retrieved hostname: %s",hostname);
		}
	}
	pt = init_mapper_st(blk,mapper_name);
	if(pt) DBG3("Mail Mapper: ignorecase %d, ignoredomain %d, mapfile %s",ignorecase,ignoredomain, mapfile);
	else DBG("Mail mapper initialization error");
	return pt;
}

