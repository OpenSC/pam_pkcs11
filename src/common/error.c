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

#include "error.h"
#include <string.h>

#define ERROR_BUFFER_SIZE 512

static char error_buffer[ERROR_BUFFER_SIZE] = "";

void set_error(char *format, ...)
{
  static char tmp[ERROR_BUFFER_SIZE];
  va_list ap;
  va_start(ap, format);
  vsnprintf(tmp, ERROR_BUFFER_SIZE, format, ap);
  va_end(ap);
  strcpy(error_buffer, tmp);
}

const char *get_error()
{
  return (const char *)error_buffer;
}
