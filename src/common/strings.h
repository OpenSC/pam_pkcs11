/*
 * PAM-PKCS11 string tools
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

#ifndef __STRINGS_H_
#define __STRINGS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifndef _STRINGS_C_
#define M_EXTERN extern
#else
#define M_EXTERN
#endif

M_EXTERN int is_empty_str(const char *str);
M_EXTERN char *clone_str(const char *str);
M_EXTERN char *toupper_str(const char *str);
M_EXTERN char *tolower_str(const char *str);
M_EXTERN char *bin2hex(const unsigned char *binstr,const int len);

#undef M_EXTERN

#endif
