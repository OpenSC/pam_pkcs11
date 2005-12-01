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
#ifndef __PKCS11_LIB_H__
#define __PKCS11_LIB_H__

#include "rsaref/pkcs11.h"

#ifndef __PKCS11_LIB_C__
#define PKCS11_EXTERN extern
#else 
#define PKCS11_EXTERN
#endif

PKCS11_EXTERN int load_pkcs11_module(char *module, pkcs11_handle_t *h);
PKCS11_EXTERN int init_pkcs11_module(pkcs11_handle_t *h);
PKCS11_EXTERN void release_pkcs11_module(pkcs11_handle_t *h);
PKCS11_EXTERN int open_pkcs11_session(pkcs11_handle_t *h, unsigned int slot);
PKCS11_EXTERN int close_pkcs11_session(pkcs11_handle_t *h);
PKCS11_EXTERN int pkcs11_login(pkcs11_handle_t *h, char *password);
PKCS11_EXTERN int get_certificates(pkcs11_handle_t *h);
PKCS11_EXTERN int get_private_keys(pkcs11_handle_t *h);
PKCS11_EXTERN int sign_value(pkcs11_handle_t *h, CK_BYTE *data, CK_ULONG length,
               CK_BYTE **signature, CK_ULONG *signature_length);
PKCS11_EXTERN int get_random_value(unsigned char *data, int length);

#undef PKCS11_EXTERN

/* end of pkcs11_lib.h */
#endif
