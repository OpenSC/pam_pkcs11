/* strndup.c
 *
 */

/* Written by Niels Möller <nisse@lysator.liu.se>
 * modified by Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * This file is hereby placed in the public domain.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_STRNDUP
char * strndup (const char *s, size_t size)
{
	char *r = NULL;
	char *end = memchr(s, 0, size);

	if (NULL == end)
		return NULL;

	/* Length */
	size = end - s;

	r = malloc(size+1);
	if (r)
	{
		memcpy(r, s, size);
		r[size] = '\0';
	}
	return r;
}
#endif
