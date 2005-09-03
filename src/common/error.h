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
 * $Id$
 */

#ifndef __ERROR_H_
#define __ERROR_H_

#include <stdarg.h>
#include <openssl/err.h>
#include <errno.h>

/** Default error message buffer size */
#define ERROR_BUFFER_SIZE 512 

#ifndef __ERROR_C_
#define ERROR_EXTERN extern
#else
#define ERROR_EXTERN
#endif

/**
* store an error message into a temporary buffer, in a similar way as sprintf does
* @param format String to be stored
* @param ... Additional parameters
*/
ERROR_EXTERN void set_error(char *format, ...);

/**
* Retrieve error message string from buffer
*@return Error message
*/
ERROR_EXTERN const char *get_error();

#undef ERROR_EXTERN
#endif /* __ERROR_H_ */
