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

#include "debug.h"
#include <stdarg.h>
#include <stdio.h>

/* current debug level */
static int debug_level = 0;

void set_debug_level(int level)
{
  debug_level = level;
}

void debug_print(int level, char *file, int line, char *format, ...)
{
  va_list ap;
  if (debug_level >= level) {
    /* print preamble */
    printf("\033[34mDEBUG:%s:%d: ", file, line);
    /* print message */
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
    /* print postamble */
    printf("\033[39m\n");
  }
}
