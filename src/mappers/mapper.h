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
#include <../common/cert_st.h>
#include "../scconf/scconf.h"

/**
* Structure to be filled on mapper module initialization
*/
typedef struct mapper_module_st {
    /** mapper name */
    const char *name; 
    /** mapper configuration block */
    scconf_block *block;
    /** debug level to set before call entry points */
    int  dbg_level; 
    /** pointer to mapper local data */
    void *context; 
    /** cert. entries enumerator */
    char **(*entries)(X509 *x509, void *context);
    /** cert. login finder */
    char *(*finder)(X509 *x509, void *context, int *match);
    /** cert-to-login matcher*/
    int (*matcher)(X509 *x509, const char *login, void *context);
    /** module de-initialization */
    void (*deinit)( void *context); 
} mapper_module;

/**
* This struct is used in processing map files
* a map file is a list of "key" " -> " "value" text lines
*/
struct mapfile {
	/** URL of mapfile */
	const char *uri;
	/** buffer to content of mapfile */
	char *buffer;
	/** lenght of buffer */
	size_t length;
	/** pointer to last readed entry in buffer */
	char *pt;
	/** key entry in current buffer */
	char *key;
	/** value assigned to key */
	char *value;
};

/* ------------------------------------------------------- */

/**
* Initialize module and mapper_module_st structure
*
* EVERY mapper module MUST provide and export this function if dinamycally linked
*@param ctx Pointer to related configuration file context
*@param mapper_name Name of this mapper. Used for multi-mapper modules
*@return Pointer to a mapper_module structure, or NULL if failed
*/
mapper_module * mapper_module_init(scconf_block *ctx,const char *mapper_name);

/* ------------------------------------------------------- */

/*
* mapper.c prototype functions
*/
#ifndef __MAPPER_C_
#define MAPPER_EXTERN extern
#else
#define MAPPER_EXTERN
#endif

/* mapfile related functions */

/**
* Initialize a mapper entry table
*@param uri Universal Resource Locator of the file to be mapped
*@return A mapfile structure pointer or NULL
*/
MAPPER_EXTERN struct mapfile *set_mapent(const char *uri);

/**
* Retrieve next entry of given map file
*@param mfile Map file entry pointer
*@return 1 on sucess, 0 on no more entries, -1 on error
*/
MAPPER_EXTERN int    get_mapent(struct mapfile *mfile);

/**
* Release a mapentry structure
*@param mfile Map file structure to be released
*/
MAPPER_EXTERN void   end_mapent(struct mapfile *mfile);

/**
* Try to map "key" to provided mapfile
*@param file URL of map file
*@param key String to be mapped
*@param ignorecase Flag to indicate upper/lowercase ignore in string compare
*@param match Set to 1 for mapped string return, unmodified for key return
*@return key on no match, else a clone_str()'d of found mapping
*/
MAPPER_EXTERN char *mapfile_find(const char *file,char *key,int ignorecase,int *match);

/**
* Try to match provided key to provided name by mean of a mapfile
*@param file URL of map file
*@param key String to be mapped
*@param value String to be matched against mapped result
*@param ignorecase Flag to indicate upper/lowercase ignore in string compare
*@return 1 on match, 0 on no match, -1 on process error
*/
MAPPER_EXTERN int mapfile_match(const char *file,char *key,const char *value,int ignorecase);

/* pwent related functions */

/**
* find the user login that matches pw_name or pw_gecos with provided item
*@param item Data to be searched from password database
*@param ignorecase Flag to check upper/lowercase in string comparisions
*@return userlogin if match found, else NULL
*/
MAPPER_EXTERN char *search_pw_entry(const char *item, int ignorecase);

/**
* Test if provided item matches pw_name or pw_gecos of provided password structure
*@param item String to be compared
*@param pw password entry to search into
*@param ignorecase Flag to check upper/lowercase in string comparisions
*@return 1 on match, 0 on no match, -1 on error
*/
MAPPER_EXTERN int compare_pw_entry(const char *item, struct passwd *pw,int ignorecase);

#undef MAPPER_EXTERN

/* ------------------------------------------------------- */

/**
* Default macro for locate certificate entry
*
* Provided as sample for debugging, not for real user
*@param x509 X509 Certificate
*@param context Mapper context
*@return String array with up to 15 results or NULL if fail
*/
#define _DEFAULT_MAPPER_FIND_ENTRIES					\
static char ** mapper_find_entries(X509 *x509, void *context) {		\
	return NULL;							\
}

/**
* Default macro for locating user
*
* Should not be used except for debugging, as always returns "nobody"
*@param x509 X509 Certificate
*@param context Mapper context
*@return Found user, or NULL
*/
#define _DEFAULT_MAPPER_FIND_USER					\
static char * mapper_find_user(X509 *x509,void *context,int *match) {		\
        if ( !x509 ) return NULL;					\
	*match = 1;							\
        return "nobody";						\
}

/**
* Macro for match mapper function
*
*@param x509 X509 Certificate
*@param login user to match, or null to find user that matches certificate
*@param context Mapper context
*@return 1 on success; login points to matched user
*	0 on no match
* 	-1 on error
*/
#define _DEFAULT_MAPPER_MATCH_USER 					\
static int mapper_match_user(X509 *x509, const char *login, void *context) { \
	int match = 0;							\
	char *username= mapper_find_user(x509,context,&match); 		\
	if (!x509) return -1;						\
	if (!login) return -1;						\
	if (!username) return 0; /*user not found*/			\
	if ( ! strcmp(login,username) ) return 1; /* match user */	\
	return 0; /* no match */					\
}

/**
* Macro for de-initialization routine
*@param context Mapper context
*/
#define _DEFAULT_MAPPER_END 						\
static void mapper_module_end(void *context) {				\
	free(context);							\
	return;								\
}									\

/**
* Macro for default init function
*@param blk Mapper Configuration file block
*@param name Name of this mapper
*@return  pointer to mapper_module data, else NULL
* NOTE: mapper module data MUST BE defined in module
*/
#define _DEFAULT_MAPPER_INIT 						\
mapper_module* mapper_module_init(scconf_block *blk,const char *name) {	\
	mapper_module *pt= malloc(sizeof (mapper_module));		\
	if (!pt) return NULL;						\
	pt->name    = name;						\
	pt->context = NULL;						\
	pt->block   = blk;						\
	pt->dbg_level  = get_debug_level();				\
	pt->entries = mapper_find_entries;				\
	pt->finder  = mapper_find_user;					\
	pt->matcher = mapper_match_user;				\
	pt->deinit  = mapper_module_end;			\
	return pt;							\
}									\

/* end of mapper.h file */
#endif
