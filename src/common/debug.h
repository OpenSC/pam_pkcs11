/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
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
 * $Id:$
 */

/**
*@def DEBUG
* This module contains macros for generate debugging messages
* Will be compiled an linked only when -DDEBUG CFLAG is used
*/

#ifndef __DEBUG_H_
#define __DEBUG_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef DEBUG

#warning "Debugging is completely disabled!"
#define DBG
#define DBG1
#define DBG2
#define DBG3
#define DBG4
#define DBG5
#define set_debug_level(l, ...) {}
#define debug(l, ...) {}

#else

/*
#define DBG(f, ...) debug_print(1, __FILE__, __LINE__, f, ## __VA_ARGS__)
*/
/* this syntax is redundant in GCC, just used to avoid warns in -pedantic */
#define DBG(f) debug_print(1, __FILE__, __LINE__, f )
#define DBG1(f,a) debug_print(1, __FILE__, __LINE__, f , a )
#define DBG2(f,a,b) debug_print(1, __FILE__, __LINE__, f , a , b )
#define DBG3(f,a,b,c) debug_print(1, __FILE__, __LINE__, f , a , b , c )
#define DBG4(f,a,b,c,d) debug_print(1, __FILE__, __LINE__, f , a , b , c , d )
#define DBG5(f,a,b,c,d,e) debug_print(1, __FILE__, __LINE__, f , a , b , c , d , e )

#define ERR(f) debug_print(-1, __FILE__, __LINE__, f )
#define ERR1(f,a) debug_print(-1, __FILE__, __LINE__, f , a )
#define ERR2(f,a,b) debug_print(-1, __FILE__, __LINE__, f , a , b )
#define ERR3(f,a,b,c) debug_print(-1, __FILE__, __LINE__, f , a , b , c )
#define ERR4(f,a,b,c,d) debug_print(-1, __FILE__, __LINE__, f , a , b , c , d )
#define ERR5(f,a,b,c,d,e) debug_print(-1, __FILE__, __LINE__, f , a , b , c , d , e )

#ifndef __DEBUG_C_
#define DEBUG_EXTERN extern
#else 
#define DEBUG_EXTERN
#endif

/**
 * set_debug_level() Sets the current debug level.
 *@param level. New debug level
 */
DEBUG_EXTERN void set_debug_level(int level);

/**
 * get_debug_level() Returns the current debug level.
 *@return Current debug level
 */
DEBUG_EXTERN int get_debug_level(void);

/**
 * debug_print() prints the given message 

 * if the current debug-level 
 * is greater or equal to the defined level. The format string as well as all
 * further arguments are interpreted as by the printf() function. 
 *@param level Debug level of message
 *@param file Name of the file where message is generated
 *@param line Line number where message is generated
 *@param format Message format
 *@param .... Optional arguments
 */
DEBUG_EXTERN void debug_print(int level, char *file, int line, char *format, ...);

#undef DEBUG_EXTERN

#endif /* DEBUG */

#endif /* __DEBUG_H_ */
