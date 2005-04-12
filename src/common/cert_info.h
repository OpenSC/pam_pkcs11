/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003-2004 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
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

#ifndef _CERT_INFO_H
#define _CERT_INFO_H

#include <openssl/x509.h>

#define CERT_CN		1	/* Certificate Common Name */
#define CERT_SUBJECT	2	/* Certificate subject */
#define CERT_KPN	3	/* Kerberos principal name */
#define CERT_EMAIL	4	/* Certificate e-mail */
#define CERT_UPN	5	/* Microsoft's Universal Principal Name */
#define CERT_UID	6	/* Certificate Unique Identifier */
#define CERT_PUK	7	/* Certificate Public Key */
#define CERT_DIGEST	8	/* Certificate Digest */

/* max number of entries to find from certificate */
#define CERT_INFO_SIZE 16
#define CERT_INFO_MAX_ENTRIES ( CERT_INFO_SIZE - 1 ) 

#ifndef _CERT_INFO_C
#define M_EXTERN extern
#else
#define M_EXTERN
#endif

/**
* request info on certificate
* @param x509 certificate to parse
* @param type information to retrieve
* @param algorithm to use in evaluate certificate digest; else null
* @return utf-8 string array with provided information
*/
M_EXTERN char **cert_info(X509 *x509, int type, const char *algorithm);

#undef M_EXTERN

#endif /* _CERT_INFO_H */
