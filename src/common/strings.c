/*
 * PAM-PKCS11 strings tools
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

#ifndef __STRINGS_C_
#define __STRINGS_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "strings.h"

/*
check for null or blank string
*/
int is_empty_str(const char *str) {
	const char *pt;
	if (!str) return 1;
	for (pt=str; *pt;pt++) if (!isspace(*pt)) return 0;
	/* arriving here means no non-blank char found */
	return 1;
}

/* returns a clone of provided string */
char *clone_str(const char *str) {
	size_t len= strlen(str);
	char *dst= (char *) malloc(1+len);
	if (!dst) return NULL;
	strncpy(dst,str,len);
	*(dst+len)='\0';
	return dst;
}

/* returns a uppercased clone of provided string */
char *toupper_str(const char *str) {
	const char *from;
	char *to;
	char *dst= (char *) malloc(1+strlen(str));
	if(!dst) return (char *) str; /* should I advise?? */
	for (from=str,to=dst;*from; from++,to++) *to=toupper(*from);
	*to='\0';
	return dst;
}

/* returns a lowercased clone of provided string */
char *tolower_str(const char *str) {
	const char *from;
	char *to;
	char *dst= (char *)malloc(1+strlen(str));
	if(!dst) return (char *)str /* should I advise?? */;
	for (from=str,to=dst;*from; from++,to++) *to=tolower(*from);
	*to='\0';
	return dst;
}

char *bin2hex(const unsigned char *binstr,const int len) {
	int i;
	char *pt;
	char *res= (char *) malloc(1+3*len);
	if (!res) return NULL;
	for(i=0,pt=res;i<len;i++,pt+=3){
	    sprintf(pt,"%02X:",binstr[i]);
	}
	*(--pt)='\0'; /* replace last ':' with '\0' */
	return res;
}

#endif /* __STRINGS_C_ */
