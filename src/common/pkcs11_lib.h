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

#include "cert_st.h"

typedef struct cert_object_str cert_object_t;
typedef struct pkcs11_handle_str pkcs11_handle_t;

#ifndef __PKCS11_LIB_C__
#define PKCS11_EXTERN extern
#else 
#define PKCS11_EXTERN
#endif

PKCS11_EXTERN int crypto_init(cert_policy *policy);
PKCS11_EXTERN int load_pkcs11_module(char *module, pkcs11_handle_t **h);
PKCS11_EXTERN int init_pkcs11_module(pkcs11_handle_t *h,int flag);
PKCS11_EXTERN int find_slot_by_number(pkcs11_handle_t *h,int slot_num,
                                      unsigned int *slot);
PKCS11_EXTERN int find_slot_by_number_and_label(pkcs11_handle_t *h,
                                      int slot_num, const char *slot_label,
                                      unsigned int *slot);
PKCS11_EXTERN const char *get_slot_tokenlabel(pkcs11_handle_t *h);
PKCS11_EXTERN int wait_for_token(pkcs11_handle_t *h,
                                 int wanted_slot_num, 
                                 const char *wanted_token_label,
                                 unsigned int *slot);
PKCS11_EXTERN int find_slot_by_slotlabel(pkcs11_handle_t *h,
                                 const char *wanted_slot_label,
                                 unsigned int *slot);
PKCS11_EXTERN int find_slot_by_slotlabel_and_tokenlabel(pkcs11_handle_t *h,
                                 const char *wanted_slot_label,
                                 const char *wanted_token_label,
                                 unsigned int *slot);
PKCS11_EXTERN int wait_for_token_by_slotlabel(pkcs11_handle_t *h,
                                 const char *wanted_slot_label, 
                                 const char *wanted_token_label,
                                 unsigned int *slot);
PKCS11_EXTERN const X509 *get_X509_certificate(cert_object_t *cert);
PKCS11_EXTERN void release_pkcs11_module(pkcs11_handle_t *h);
PKCS11_EXTERN int open_pkcs11_session(pkcs11_handle_t *h, unsigned int slot);
PKCS11_EXTERN int close_pkcs11_session(pkcs11_handle_t *h);
PKCS11_EXTERN int pkcs11_login(pkcs11_handle_t *h, char *password);
PKCS11_EXTERN int pkcs11_pass_login(pkcs11_handle_t *h, int nullok);
PKCS11_EXTERN cert_object_t **get_certificate_list(pkcs11_handle_t *h, 
                                                  int *ncert);
PKCS11_EXTERN int get_private_key(pkcs11_handle_t *h, cert_object_t *);
PKCS11_EXTERN int sign_value(pkcs11_handle_t *h, cert_object_t *,
               unsigned char *data, unsigned long length,
               unsigned char **signature, unsigned long *signature_length);
PKCS11_EXTERN int get_random_value(unsigned char *data, int length);

#undef PKCS11_EXTERN

/* end of pkcs11_lib.h */
#endif
