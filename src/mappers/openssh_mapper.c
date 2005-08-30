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

#define __OPENSSH_MAPPER_C_

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
#include "openssh_mapper.h"

/* TODO 
Not sure on usage of authorized keys map file...
So the first version, will use getpwent() to navigate across all users 
and parsing ${userhome}/.ssh/authorized_keys
*/
static const char *keyfile="/etc/pam_pkcs11/authorized_keys";

/**
* This mapper try to locate user by comparing authorized public keys
* from each $HOME/.ssh user entry, as done in openssh package
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
* Returns the public key of certificate as an array list
*/
static char ** openssh_mapper_find_entries(X509 *x509) {
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
static char * openssh_mapper_find_user(X509 *x509) {
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
	    sprintf(filename,"%s/.ssh/authorized_keys",pw->pw_dir);
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
            DBG1("No cert pubkey match found for user '%s'",pw->pw_name);
	    fclose(fd);
        } /* next login */
	/* no user found that contains key in their authorized_key file */
	endpwent();
        DBG("No ${login}/.ssh/authorized_keys maps to any provided public key");
        return NULL;
}

/*
* parses the certificate, extract public key and try to match
* with contents of ${login}/.ssh/authorized_keys file
* returns -1, 0 or 1 ( error, no match, or match)
*/
static int openssh_mapper_match_user(X509 *x509, const char *login) {
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
	sprintf(filename,"%s/.ssh/authorized_keys",pw->pw_dir);
	fd=fopen(filename,"rt");
	if (!fd) {
	    DBG2("fopen('%s') : '%s'",filename,strerror(errno));
	    return -1; /* no authorized_keys file -> no match :-) */
	}
        for (str=*entries; str ; str=*++entries) {
		int res = match_keyfile(str,fd);
		if( res<0) return -1;
		if( res==0) continue; /* no match, try next public key */
		/* arriving here means cert public key match */
		fclose(fd);
		return res;
        }
	fclose(fd);
        DBG("User authorized_keys file doesn't match cert public key(s)");
        return 0;
}

_DEFAULT_MAPPER_END

#ifndef OPENSSH_MAPPER_STATIC
struct mapper_module_st mapper_module_data;
                                                                                
static void init_mapper_st(scconf_block *blk, const char *name) {
        mapper_module_data.name = name;
        mapper_module_data.block =blk;
        mapper_module_data.entries = openssh_mapper_find_entries;
        mapper_module_data.finder = openssh_mapper_find_user;
        mapper_module_data.matcher = openssh_mapper_match_user;
        mapper_module_data.mapper_module_end = mapper_module_end;
}

#else
struct mapper_module_st openssh_mapper_module_data;
                                                                                
static void init_mapper_st(scconf_block *blk, const char *name) {
        openssh_mapper_module_data.name = name;
        openssh_mapper_module_data.block =blk;
        openssh_mapper_module_data.entries = openssh_mapper_find_entries;
        openssh_mapper_module_data.finder = openssh_mapper_find_user;
        openssh_mapper_module_data.matcher = openssh_mapper_match_user;
        openssh_mapper_module_data.mapper_module_end = mapper_module_end;
}
#endif

/**
* Initialization routine
*/
#ifndef OPENSSH_MAPPER_STATIC
int mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
int openssh_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
        int debug;
        if (!blk) return 0; /* should not occurs, but... */
        debug      = scconf_get_bool(blk,"debug",0);
        keyfile    = scconf_get_str(blk,"keyfile",keyfile);
        set_debug_level(debug);
        DBG2("OpenSSH mapper started. debug: %d, mapfile: %s",debug,keyfile);
	init_mapper_st(blk,mapper_name);
        return 1;
}
