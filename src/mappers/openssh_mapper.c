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
#ifndef HAVE_NSS
#include <openssl/opensslv.h>
#include "../common/pam-pkcs11-ossl-compat.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#endif

#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/base64.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "mapper.h"
#include "openssh_mapper.h"

/* TODO
Not sure on usage of authorized keys map file...
So the first version, will use getpwent() to navigate across all users
and parsing ${userhome}/.ssh/authorized_keys
*/
static const char *keyfile=CONFDIR "/authorized_keys";
static int debug=0;

/**
* This mapper try to locate user by comparing authorized public keys
* from each $HOME/.ssh user entry, as done in openssh package
*/

#define OPENSSH_LINE_MAX 8192	/* from openssh SSH_MAX_PUBKEY_BYTES */

#ifndef HAVE_NSS
static EVP_PKEY *ssh1_line_to_key(char *line) {
	EVP_PKEY *key;
	RSA *rsa;
	BIGNUM *rsa_n, *rsa_e;
	char *b, *e, *m, *c;

	key = EVP_PKEY_new();
	if (!key) return NULL;
	rsa = RSA_new();
	if (!rsa) goto err;

	/* first digitstring: the bits */
	b = line;
	/* second digitstring: the exponent */
	/* skip all digits */
	for (e = b; *e >= '0' && *e <= '0'; e++) ;
	/* must be a whitespace */
	if (*e != ' ' && *e != '\t') return NULL;
	/* cut the string in two part */
	*e = 0;
	e++;
	/* skip more whitespace */
	while (*e == ' ' || *e == '\t') e++;
	/* third digitstring: the modulus */
	/* skip all digits */
	for (m = e; *m >= '0' && *m <= '0'; m++) ;
	/* must be a whitespace */
	if (*m != ' ' && *m != '\t') return NULL;

	/* cut the string in two part */
	*m = 0;
	m++;

	/* skip more whitespace */
	while (*m == ' ' || *m == '\t') m++;

	/* look for a comment after the modulus */
	for (c = m; *c >= '0' && *c <= '0'; c++) ;

	/* could be a whitespace or end of line */
	if (*c != ' ' && *c != '\t' && *c != '\n' && *c != '\r' && *c != 0) return NULL;

	if (*c == ' ' || *c == '\t') {
		*c = 0;
		c++;

		/* skip more whitespace */
		while (*c == ' ' || *c == '\t') c++;

		if (*c && *c != '\r' && *c != '\n') {
			/* we have a comment */
		} else {
			c = NULL;
		}

	} else {
		*c = 0;
		c = NULL;
	}

	/* ok, now we have b e m pointing to pure digit
	 * null terminated strings and maybe c pointing to a comment */

	BN_dec2bn(&rsa_e, e);
	BN_dec2bn(&rsa_n, m);
	RSA_set0_key(rsa, rsa_e, rsa_n,NULL);

	EVP_PKEY_assign_RSA(key, rsa);
	return key;

      err:
	free(key);
	return NULL;
}

static EVP_PKEY *ssh2_line_to_key(char *line) {
	EVP_PKEY *key;
	RSA *rsa;
	BIGNUM *rsa_e, *rsa_n;
	unsigned char decoded[OPENSSH_LINE_MAX];
	int len;

	char *b, *c;
	int i;

	/* find the mime-blob */
	b = line;
	if (!b) return NULL;

	/* find the first whitespace */
	while (*b && *b != ' ') b++;
	/* skip that whitespace */
	b++;
	/* find the end of the blob / comment */
	for (c = b; *c && *c != ' ' && 'c' != '\t' && *c != '\r' && *c != '\n'; c++) ;
	*c = 0;
	/* decode binary data */
	if (base64_decode(b, decoded, OPENSSH_LINE_MAX) < 0) return NULL;

	i = 0;
	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* now: key_from_blob */
	if (strncmp((char *)&decoded[i], "ssh-rsa", 7) != 0) return NULL;
	i += len;

	key = EVP_PKEY_new();
	rsa = RSA_new();

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* get bignum */
	rsa_e = BN_bin2bn(decoded + i, len, NULL);
	i += len;

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* get bignum */
	rsa_n = BN_bin2bn(decoded + i, len, NULL);

	RSA_set0_key(rsa, rsa_n, rsa_e, NULL);
	EVP_PKEY_assign_RSA(key, rsa);
	return key;
}

static void add_key(EVP_PKEY * key, EVP_PKEY *** keys, int *nkeys) {
	EVP_PKEY **keys2;
	/* sanity checks */
	if (!key) return;
	if (!keys) return;
	if (!nkeys) return;
	/* no keys so far */
	if (!*keys) {
		*keys = malloc(sizeof(void *));
		if (!*keys) return;
		*keys[0] = key;
		*nkeys = 1;
		return;
	}
	/* enlarge */
	keys2 = malloc(sizeof(void *) * ((*nkeys) + 1));
	if (!keys2) return;
	memcpy(keys2, *keys, sizeof(void *) * (*nkeys));
	keys2[*nkeys] = key;
	free(*keys);
	*keys = keys2;
	(*nkeys)++;
}
#endif

/*
* Returns the public key of certificate as an array list
*/
static char ** openssh_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_SSHPUK,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_public_key() failed");
                return NULL;
        }
        return entries;
}

static int openssh_mapper_match_keys(X509 *x509, const char *filename) {
#ifdef HAVE_NSS
	return -1;
#else
	FILE *fd;
	char line[OPENSSH_LINE_MAX];
	int i;
	int nkeys =0;
	EVP_PKEY **keys = NULL;
	EVP_PKEY *authkey = X509_get_pubkey(x509);

	if (!authkey) {
	    DBG("Cannot locate Cert Public key");
	    return 0;
        }
        /* parse list of authorized keys until match */
	fd=fopen(filename,"rt");
	if (!fd) {
	    DBG2("fopen('%s') : '%s'",filename,strerror(errno));
	    return 0; /* no authorized_keys file -> no match :-) */
	}
	/* read pkey files and compose chain */
	for (;;) {
                char *cp;
                if (!fgets(line, OPENSSH_LINE_MAX, fd)) break;
                /* Skip leading whitespace, empty and comment lines. */
                for (cp = line; *cp == ' ' || *cp == '\t'; cp++)

                        if (!*cp || *cp == '\n' || *cp == '#') continue;
                if (*cp >= '0' && *cp <= '9') {
                        /* ssh v1 key format */
                        EVP_PKEY *key = ssh1_line_to_key(cp);
                        if (key) add_key(key, &keys, &nkeys);
                }
                if (strncmp("ssh-rsa", cp, 7) == 0) {
                        /* ssh v2 rsa key format */
                        EVP_PKEY *key = ssh2_line_to_key(cp);
                        if (key) add_key(key, &keys, &nkeys);
	    }
        }
	fclose(fd);
        for (i = 0; i < nkeys; i++) {
                RSA *authrsa, *rsa;
                BIGNUM *authrsa_n, *authrsa_e;
                BIGNUM *rsa_n, *rsa_e;
                authrsa = EVP_PKEY_get1_RSA(authkey);
                if (!authrsa) continue;       /* not RSA */
                rsa = EVP_PKEY_get1_RSA(keys[i]);
                if (!rsa) continue;       /* not RSA */

                authrsa_e = RSA_get0_e(authrsa);
                rsa_e = RSA_get0_e(rsa);
                if (BN_cmp(rsa_e, authrsa_e) != 0) continue;

                authrsa_n = RSA_get0_n(authrsa);
                rsa_n = RSA_get0_n(rsa);
                if (BN_cmp(rsa_n, authrsa_n) != 0) continue;
                return 1;       /* FOUND */
        }
        DBG("User authorized_keys file doesn't match cert public key(s)");
        return 0;
#endif
}

_DEFAULT_MAPPER_END

/*
* parses the certificate, extract public key and try to match
* with contents of ${login}/.ssh/authorized_keys file
* returns -1, 0 or 1 ( error, no match, or match)
*/
static int openssh_mapper_match_user(X509 *x509, const char *user, void *context) {
        struct passwd *pw;
	char filename[PATH_MAX];
        if (!x509) return -1;
        if (!user) return -1;
        pw = getpwnam(user);
        if (!pw || is_empty_str(pw->pw_dir) ) {
            DBG1("User '%s' has no home directory",user);
            return -1;
        }
	sprintf(filename,"%s/.ssh/authorized_keys",pw->pw_dir);
        return openssh_mapper_match_keys(x509,filename);
}

/*
parses the certificate and return the _first_ user that matches public key
*/
static char * openssh_mapper_find_user(X509 *x509, void *context, int *match) {
        int n = 0;
        struct passwd *pw = NULL;
        char *res = NULL;
        /* parse list of users until match */
        setpwent();
        while((pw=getpwent()) != NULL) {
	    char filename[PATH_MAX];
            DBG1("Trying to match certificate with user: '%s'",pw->pw_name);
            if ( is_empty_str(pw->pw_dir) ) {
                DBG1("User '%s' has no home directory",pw->pw_name);
                continue;
            }
	    sprintf(filename,"%s/.ssh/authorized_keys",pw->pw_dir);
            n = openssh_mapper_match_keys (x509,filename);
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
            res = clone_str(pw->pw_name);
            endpwent();
	    *match = 1;
	    return res;
        } /* next login */
        /* no user found that contains cert in their directory */
        endpwent();
        DBG("No entry at ${login}/.ssh/authorized_keys maps to any provided certificate");
        return NULL;
}

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = openssh_mapper_find_entries;
	pt->finder = openssh_mapper_find_user;
	pt->matcher = openssh_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

/**
* Initialization routine
*/
#ifndef OPENSSH_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * openssh_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;
        if (blk) {
        debug      = scconf_get_bool(blk,"debug",0);
        keyfile    = scconf_get_str(blk,"keyfile",keyfile);
	} else {
		DBG1("No block declaration for mapper '%s'",mapper_name);
	}
        set_debug_level(debug);
	pt = init_mapper_st(blk,mapper_name);
        if(pt) DBG2("OpenSSH mapper started. debug: %d, mapfile: %s",debug,keyfile);
	else DBG("OpenSSH mapper initialization failed");
        return pt;
}
