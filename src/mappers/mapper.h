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
typedef struct mapper_module_st {
	const char *name; /* mapper name */
	scconf_block *block; /* mapper configuration block */
    int  dbg_level; /* debug level to set before call entry points */
    void *context; 		/* pointer to mapper local data */
    char **(*entries)(X509 *x509, void *context); /* cert. entries enumerator */
    char *(*finder)(X509 *x509, void *context); /* cert. login finder */
    int (*matcher)(X509 *x509, const char *login, void *context); /*cert-to-login matcher*/
    void (*deinit)( void *context); 	/* module de-initialization */
} mapper_module;

/*
* This struct is used in processing map files
* a map file is a list of "key" " -> " "value" text lines
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
mapper_module * mapper_module_init(scconf_block *ctx,const char *mapper_name);

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
static char ** mapper_find_entries(X509 *x509, void *context) {		\
	return NULL;							\
}

/**
* default macro for locating user
* Should not be used except for debugging, as allways returns "nobody"
*/
#define _DEFAULT_MAPPER_FIND_USER					\
static char * mapper_find_user(X509 *x509,void *context) {		\
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
static int mapper_match_user(X509 *x509, const char *login, void *context) { \
	char *username= mapper_find_user(x509,context); 			\
	if (!x509) return -1;						\
	if (!login) return -1;						\
	if (!username) return 0; /*user not found*/			\
	if ( ! strcmp(login,username) ) return 1; /* match user */	\
	return 0; /* no match */					\
}

/** 
* Macro for de-initialization routine
*/
#define _DEFAULT_MAPPER_END 						\
static void mapper_module_end(void *context) {				\
	free(context);							\
	return;								\
}									\

/**
* Macro for default init function
* returns pointer to mapper_module data, else NULL
* NOTE: mapper module data MUST BE defined in module
*/
#define _DEFAULT_MAPPER_INIT 						\
mapper_module* mapper_module_init(scconf_block *blk,const char *name) {	\
	mapper_module *pt= malloc(sizeof (mapper_module));		\
	if (!pt) return NULL;						\
	pt->name    = name;						\
	pt->context = NULL;						\
	pt->block   = blk;						\
	pt->entries = mapper_find_entries;				\
	pt->finder  = mapper_find_user;					\
	pt->matcher = mapper_match_user;				\
	pt->deinit  = mapper_module_end;			\
	return pt;							\
}									\

/* end of mapper.h file */
#endif
