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

#ifndef __MAPPER_C_
#define __MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <regex.h>
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/uri.h"
#include "../common/strings.h"
#include "mapper.h"

/*
* Common functions to all mapping modules
*/

/**
* Initialize a map file
* Creates a mapfile entry
* load url and store into mapfile
* returns struct or NULL on error
*/
struct mapfile *set_mapent(const char *url) {
	int res;
	struct mapfile *mfile = malloc(sizeof(struct mapfile));
	if (!mfile) return NULL;
	mfile->uri=url;
	mfile->pt = (char *) NULL;
	mfile->key = (char *) NULL;
	mfile->value = (char *) NULL;
	res = get_from_uri(mfile->uri,(unsigned char **)&mfile->buffer,&mfile->length);
	if (res<0) {
		DBG1("get_from_uri() error: %s",get_error());
		free(mfile);
		return NULL;
	}
	mfile->pt = mfile->buffer;
	return mfile;
}

/**
* Gets a key/value pair on provided mapfile
* returns true (1) on success, false (0) on error
*/
int get_mapent(struct mapfile *mfile) {
	char *res;
	char *sep;
	size_t len;
	char *from,*to;
	/* set up environment */
	free (mfile->key);
	mfile->key=NULL;
	mfile->value=NULL;
try_again:
	/* get a line from buffer */
	from = mfile->pt;
	/* set up pointer */
	while( *from && isspace(*from) ) from++;
	if(!*from) return 0;
	to = strchr(from,'\n');
	/* if no newline, assume string ends at end of buffer */
	if (!to) to=mfile->buffer+mfile->length;
	if (to<=from) {
		DBG("EOF reached");
		return 0; /* empty data */
	}
	/* store and parse line */
	len= to-from;
	res=malloc (len+1);
	if (!res) {
		DBG("malloc error");
		return 0; /* not enough space to malloc string */
	}
	strncpy(res,from,len);
	*(res+len)='\0';
	if ('#' == res[0]) {
		DBG1("Line '%s' is a comment: skip",res);
		free(res);
		mfile->pt=to;
		goto try_again; /* repeat loop */
	}
	sep = strstr(res," -> ");
	if (!sep) {
		DBG1("Line '%s' has no key -> value format: skip",res);
		free(res);
		mfile->pt=to;
		goto try_again; /* repeat loop */
	}
	*sep='\0';
	mfile->key=res;
	mfile->value=sep+4;
	mfile->pt=to;
	DBG2("Found key: '%s' value '%s'",mfile->key,mfile->value);
	return 1;
}

/**
* closes and free a mapfile entry
*/
void end_mapent(struct mapfile *mfile) {
	if (!mfile) return;
	/* don't free uri: is a scconf provided "const char *" */;
	/* free (mfile->uri); */
	/* don't free key/value: they are pointers to somewhere in buffer */
	/* free (mfile->value); */
	/* free (mfile->key); */
	free (mfile->buffer);
	free(mfile);
	return;
}

/**
* find a map from mapfile
* @param file FileName
* @param key  Key to search in mapfile
* @param icase ignore case
* @param match Set to 1 for mapped string return, unmodified for key return
* @return mapped string on match, key on no match, NULL on error
*/
char *mapfile_find(const char *file, char *key, int icase, int *match) {
	struct mapfile *mfile;
	if ( (!key) || is_empty_str(key) ) {
		DBG("key to map is null or empty");
		return NULL;
	}
	if ( (!file)||(is_empty_str((char *)file))||(!strcmp(file,"none")) ) {
		char *res = clone_str(key);
		DBG("No mapping file specified");
		return res;
	}
	DBG2("Using mapping file: '%s' to search '%s'",file,key);
        mfile = set_mapent(file);
	if (!mfile) {
		DBG1("Error processing mapfile %s",file);
                return NULL;
	}
	while (get_mapent(mfile)) {
	    int done = 0;
	    if (mfile->key[0]=='^' && mfile->key[strlen(mfile->key)-1]=='$') {
		regex_t re;
		DBG2("Trying RE '%s' match on '%s'",mfile->key,key);
		if (regcomp(&re,mfile->key,(icase ? REG_ICASE : 0)|REG_NEWLINE)) {
		    DBG2("RE '%s' in mapfile '%s' is invalid",mfile->key,file);
		} else {
		    done = !regexec(&re,key,0,NULL,0);
		    regfree(&re);
		}
	    } else if (icase)
	    	done = !strcasecmp(key, mfile->key);
	    else
	    	done = !strcmp(key, mfile->key);

            if (done) {
                char *res=clone_str(mfile->value);
                DBG2("Found mapfile match '%s' -> '%s'",key,mfile->value);
                end_mapent(mfile);
		*match = 1;
                return res;
            }
	}
	/* arriving here means map not found, so return key as result */
        DBG("Mapfile match not found");
        end_mapent(mfile);
        return clone_str(key);
}

/**
* find a match from mapfile
* @param file FileName
* @param key  Key to search in mapfile
* @param value string to match in mapfile
* @param icase ignore upper/lower case
* @return 1 on match, 0 on no match, -1 on error
*/
int mapfile_match(const char *file, char *key, const char *value, int icase) {
	int res;
	int match = 0;
	char *str=mapfile_find(file,key,icase,&match);
	if (!str) return -1;
	if (icase) res= (!strcasecmp(str,value))? 1:0;
	else       res= (!strcmp(str,value))? 1:0;
	return res;
}

/* pwent related functions */

/**
* Compare item to gecos or login pw_entry
* returns 1 on match, else 0
*/
int compare_pw_entry(const char *str,struct passwd *pw, int ignorecase) {
   if (ignorecase) {
      if ( !strcasecmp(pw->pw_name,str) || !strcasecmp(pw->pw_gecos,str) ) {
            return 1;
      }
   } else {
      if ( !strcmp(pw->pw_name,str) || !strcmp(pw->pw_gecos,str) ) {
            return 1;
      }
   }
   return 0;
}

/**
* look in pw entries for an item that matches gecos or login to provided string
* on success return login
* on fail return null
*/
char *search_pw_entry(const char *str,int ignorecase) {
	char *res;
        struct passwd *pw;
        setpwent(); /* reset pwent parser */
        while ( (pw=getpwent()) != NULL) {
            if( compare_pw_entry(str,pw,ignorecase) ) {
               DBG1("getpwent() match found: '%s'",pw->pw_name);
               res= clone_str(pw->pw_name);
	       endpwent();
	       return res;
            }
        }
        endpwent();
        DBG1("No pwent found matching string '%s'",str);
        return NULL;
}

#endif
