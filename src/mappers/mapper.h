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

#ifndef __MAPPER_H_
#define __MAPPER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <openssl/x509.h>
#include "../scconf/scconf.h"

/**
* Structure to be filled on mapper module initialization 
*/
struct mapper_module_st {
	const char *name; /* mapper name */
	scconf_block *block; /* mapper configuration block */
        char **(*entries)(X509 *x509); /* certificate entries enumerator */
        char *(*finder)(X509 *x509); /* certificate login finder */
        int (*matcher)(X509 *x509, const char *login); /*cert-to-login matcher*/
        void (*mapper_module_end)(void); /* module de-initialization */
};

/*
* This struct is used in processing map files
* a map file is a list of "key" "->" "value" text lines
*/
struct mapfile {
	const char *uri;/* URL of mapfile */
	char *buffer;	/* buffer to content of mapfile */
	size_t length;  /* lenght of buffer */
	char *pt;	/* pointer to last readed entry in buffer */
	char *key;	/* key entry in current buffer */
	char *value;    /* value assigned to key */
};

/* ------------------------------------------------------- */

/**
* Initialize module and mapper_module_st structure
* EVERY mapper module MUST provide and export this function
* returns 1 on success, 0 on error
*/
int mapper_module_init(scconf_block *ctx,const char *mapper_name);

#if 1
/* 
pkcs11-login version 0.5 or lower mapper API requires 
all these functions to be defined
*/

/**
* Get Certificate entry value whitout doing any mapping
* returns array list of found entries (null terminated)
*/
char **mapper_find_entries(X509 *x509);

/**
* User finder function.
* Can be assumed as find_entry+map_user
* returns matched user name
*         NULL on error
*/
char *mapper_find_user(X509 *x509);

/*
* user matcher function
* Can be assumed to be as find_entry() + map_user + compare_user
*
* @param x509 X509 Certificate
* @param login user to match, or null to find user that matches certificate
* @return 1 on success; login points to matched user
*	0 on no match
* 	-1 on error
*/
int mapper_match_user(X509 *x509, const char *login);

#endif

/* ------------------------------------------------------- */

/**
* mapper.c prototype functions
*/
#ifndef _MAPPER_C_
#define M_EXTERN extern
#else
#define M_EXTERN
#endif

/* mapfile related functions */
M_EXTERN struct mapfile *set_mapent(const char *uri);
M_EXTERN int    get_mapent(struct mapfile *mfile);
M_EXTERN void   end_mapent(struct mapfile *mfile);
M_EXTERN char *mapfile_find(const char *file,char *key,int ignorecase);
M_EXTERN int mapfile_match(const char *file,char *key,const char *value,int ignorecase);

/* pwent related functions */
M_EXTERN char *search_pw_entry(const char *item, int ignorecase);
M_EXTERN int compare_pw_entry(const char *item, struct passwd *pw,int ignorecase);
#undef M_EXTERN

/* ------------------------------------------------------- */

/**
* default macro for locate certificate entry
* provided as sample for debugging, not for real user
*/
#define _DEFAULT_MAPPER_FIND_ENTRIES					\
static char ** mapper_find_entries(X509 *x509) {			\
	return NULL;							\
}

/**
* default macro for locating user
* Should not be used except for debugging, as allways returns "nobody"
*/
#define _DEFAULT_MAPPER_FIND_USER					\
static char * mapper_find_user(X509 *x509) {				\
        if ( !x509 ) return NULL;					\
        return "nobody";						\
}

/*
* inlined function to be used as macro into modules
* @param x509 X509 Certificate
* @login user to match, or null to find user that matches certificate
* @return 1 on success; login points to matched user
*	0 on no match
* 	-1 on error
*/
#define _DEFAULT_MAPPER_MATCH_USER 					\
static int mapper_match_user(X509 *x509, const char *login) {		\
	char *username= mapper_find_user(x509); 			\
	if (!x509) return -1;						\
	if (!login) return -1;						\
	if (!username) return 0; /*user not found*/			\
	if ( ! strcmp(login,username) ) return 1; /* match user */	\
	return 0; /* no match */					\
}

/**
* Macro for default init function
* returns 1 on success, 0 on error
*/
#define _DEFAULT_MAPPER_INIT 						\
int mapper_module_init(scconf_block *blk,const char *mapper_name) {	\
	return 1;							\
}									\

/** 
* Macro for de-initialization routine
*/
#define _DEFAULT_MAPPER_END 						\
static void mapper_module_end(void) {					\
	return;								\
}									\

/* end of mapper.h file */
#endif
