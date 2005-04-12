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

#ifndef _CERT_VFY_H
#define _CERT_VFY_H

#include <openssl/x509.h>

typedef enum { CRLP_NONE, CRLP_ONLINE, CRLP_OFFLINE, CRLP_AUTO } crl_policy_t;

int verify_certificate(X509 * x509, char *ca_dir, char *crl_dir, crl_policy_t policy);

int verify_signature(X509 * x509, unsigned char *data, int data_length,
                     unsigned char *signature, int signature_length);

#endif /* _CERT_VFY_H */
