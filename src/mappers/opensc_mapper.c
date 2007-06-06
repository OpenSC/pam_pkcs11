/*
 * PAM-PKCS11 OPENSSH mapper module
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
 * pam_pkcs11 is copyright (C) 2003-2004 of Mario Strasser <mast@gmx.net>
 *
 * Based in pam_opensc from Andreas Jellinghaus <aj@dungeon.inka.de>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "../common/cert_st.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "opensc_mapper.h"

/**
* This mapper try to locate user by comparing authorized certificates
* from each $HOME/.eid/authorized_certificates user entry, 
* as stored by OpenSC package
*/

/*
* Return the list of certificates as an array list
*/
static char ** opensc_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_PEM,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_certificate() failed");
                return NULL;
        }
        return entries;
}

/*
* parses the certificate, extract it in PEM format, and try to match
* with contents of ${login}/.ssh/authorized_certificates file
* returns -1, 0 or 1 ( error, no match, or match)
*/
static int opensc_mapper_match_certs(X509 *x509, const char *home) {
        char filename[PATH_MAX];
        X509 **certs;
        int ncerts, i, rc;
#ifdef HAVE_NSS
	/* still need to genericize the BIO functions here */
	return -1;
#else
#include <openssl/pem.h>
        BIO *in;

        if (!x509) return -1;
        if (!home) return -1;

        snprintf(filename, PATH_MAX, "%s/.eid/authorized_certificates", home);

        in = BIO_new(BIO_s_file());
        if (!in) {
            DBG("BIO_new() failed\n");
	    return -1;
	}

        rc = BIO_read_filename(in, filename);
        if (rc != 1) {
             DBG1("BIO_read_filename from %s failed\n",filename);
             return 0; /* fail means no file, or read error */
        }
	/* create and compose certificate chain */
        ncerts=0; certs=NULL;
        for (;;) {
                X509 *cert = PEM_read_bio_X509(in, NULL, 0, NULL);
                if (cert) add_cert(cert, &certs, &ncerts);
                else break;
        }
        BIO_free(in);

        for (i = 0; i < ncerts; i++) {
            if (X509_cmp(certs[i],x509) == 0) return 1; /* Match found */
        }
        return 0; /* Don't match */
#endif
}

static int opensc_mapper_match_user(X509 *x509, const char *user, void *context) {
	struct passwd *pw;
	if (!x509) return -1;
	if (!user) return -1;
	pw = getpwnam(user);
        if (!pw || !pw->pw_dir) {
		DBG1("User '%s' has no home directory",user);
                return -1;
        }
	return opensc_mapper_match_certs(x509,pw->pw_dir);
}

/*
parses the certificate and return the _first_ user that has it in
their ${HOME}/.eid/authorized_certificates
*/
static char * opensc_mapper_find_user(X509 *x509, void *context) {
	int n = 0;
	struct passwd *pw = NULL;
	char *res = NULL;
        /* parse list of users until match */
	setpwent();
	while((pw=getpwent()) != NULL) {
	    DBG1("Trying to match certificate with user: '%s'",pw->pw_name);
	    n = opensc_mapper_match_certs (x509, pw->pw_dir);
	    if (n<0) {
		DBG1("Error in matching process with user '%s'",pw->pw_name);
		endpwent();
		return NULL;
	    }
	    if (n==0) {
		DBG1("Certificate doesn't match user '%s'",pw->pw_name);
	        continue;
	    }
	    /* arriving here means user found */
            DBG1("Certificate match found for user '%s'",pw->pw_name);
	    res= clone_str(pw->pw_name);
		    endpwent();
	    return res;
        } /* next login */
	/* no user found that contains cert in their directory */
	endpwent();
        DBG("No entry at ${login}/.eid/authorized_certificates maps to any provided certificate");
        return NULL;
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
