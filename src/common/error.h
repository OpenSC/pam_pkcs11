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

#ifndef ERROR_H
#define ERROR_H

#include <stdarg.h>
#include <openssl/err.h>
#include <errno.h>

/*
 * Sets the last error message.
 */
void set_error(char *format, ...);

/*
 * Gets the last error message.
 */
const char *get_error();

#endif /* ERROR_H */
