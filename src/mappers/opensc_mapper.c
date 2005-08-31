/*
 * PAM-PKCS11 OPENSSH mapper module
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

#define __OPENSC_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "opensc_mapper.h"

/**
* This mapper try to locate user by comparing authorized public keys
* from each $HOME/.ssh user entry, as done in opensc package
*/

static int match_key(char *certkey, char *filekey) {
	if ( strstr(filekey,certkey) ) return 1;
	return 0;
}

static int match_keyfile(char *certkey,FILE *file) {
	char line[2048];
	int res;
	while(fgets(line,2048,file)!= NULL ) {
		char *pt;
		/* Ensure end of string and strip EOL */
		line[2048]='\0';
		if (line[0]=='#') continue; /* skip comments */
		if (line[strlen(line)-1]=='\n') line[strlen(line)-1] ='\0'; 
		if (is_empty_str(line)) continue; /* skip blank lines */
		pt = strstr(line,"ssh-dss ");
		if (!pt) pt = strstr(line,"ssh-rsa ");
		if (!pt) {
			/* TODO: parse old style (ssh-v1) keys */
			DBG1("Unknown line format found: '%s'",line);
			continue;
		}
		res= match_key(certkey,pt);
		if (res<=0) continue; /* not a key or key doesn't match*/
		return res; /* match found */
	}
	/* end of keyfile without match */
	return 0;
}

/*
* Returns the list of certificates as an array list
*/
static char ** opensc_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_SSHPUK,NULL);
        if (!entries) {
                DBG("get_public_key() failed");
                return NULL;
        }
        return entries;
}

/*
parses the certificate and return the _first_ user that matches public key 
*/
static char * opensc_mapper_find_user(X509 *x509, void *context) {
        char *str;
	int n;
	struct passwd *pw;
	FILE *fd;
	char filename[512];
        char **entries  = cert_info(x509,CERT_SSHPUK,NULL);
        if (!entries) {
            DBG("get_public_key() failed");
            return NULL;
        }
        /* parse list of users until match */
	setpwent();
	while((pw=getpwent()) != NULL) {
            /* parse list of authorized keys until match */
	    sprintf(filename,"%s/.eid/authorized_certificates",pw->pw_dir);
	    fd=fopen(filename,"rt");
	    if (!fd) {
	        /* DBG2("fopen('%s') : '%s'",filename,strerror(errno)); */
	        continue;
	    }
            for (n=0,str=entries[n]; str ; str=entries[n++]) {
		    int res = match_keyfile(str,fd);
		    if( res<0) return NULL;
		    if( res==0) continue; /* no match, try next public key */
		    /* arriving here means cert public key match */
		    str= clone_str(pw->pw_name);
		    fclose(fd);
		    endpwent();
		    return str;
            }
            DBG1("No certificate match found for user '%s'",pw->pw_name);
	    fclose(fd);
        } /* next login */
	/* no user found that contains key in their authorized_key file */
	endpwent();
        DBG("No entry at ${login}/.eid/authorized_certificates maps to any provided certificate");
        return NULL;
}

/*
* parses the certificate, extract public key and try to match
* with contents of ${login}/.ssh/authorized_keys file
* returns -1, 0 or 1 ( error, no match, or match)
*/
static int opensc_mapper_match_user(X509 *x509, const char *login, void *context) {
	char filename[512];
	FILE *fd;
        char *str;
        struct passwd *pw = getpwnam(login);
        char **entries  = cert_info(x509,CERT_SSHPUK,NULL);
        if (!entries) {
            DBG("get_public_key() failed");
            return -1;
        }
        if (!pw) {
            DBG1("There are no pwentry for login '%s'",login);
            return -1;
        }
        /* parse list of authorized keys until match */
	sprintf(filename,"%s/.eid/authorized_certificates",pw->pw_dir);
	fd=fopen(filename,"rt");
	if (!fd) {
	    DBG2("fopen('%s') : '%s'",filename,strerror(errno));
	    return -1; /* no authorized_certificates file -> no match :-) */
	}
        for (str=*entries; str ; str=*++entries) {
		int res = match_keyfile(str,fd);
		if( res<0) return -1;
		if( res==0) continue; /* no match, try next certificate */
		/* arriving here means certificate match */
		fclose(fd);
		return res;
        }
	fclose(fd);
        DBG("User authorized_certificates file doesn't match provided one");
        return 0;
}

_DEFAULT_MAPPER_END

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = opensc_mapper_find_entries;
	pt->finder = opensc_mapper_find_user;
	pt->matcher = opensc_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

/**
* Initialization routine
*/
#ifndef OPENSC_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * opensc_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
        int debug = 0;
        if (blk) debug = scconf_get_bool(blk,"debug",0);
        set_debug_level(debug);
	pt = init_mapper_st(blk,mapper_name);
        if(pt) DBG1("OpenSC mapper started. debug: %d",debug);
	else DBG("OpenSC mapper initialization failed");
        return pt;
}
