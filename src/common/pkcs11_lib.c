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

#define __PKCS11_LIB_C__

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "rsaref/pkcs11.h"
#include "pkcs11_lib.h"
#include "debug.h"
#include "error.h"

int load_pkcs11_module(char *module, pkcs11_handle_t *h)
{
  int rv;
  struct stat module_stat;
  CK_C_GetFunctionList C_GetFunctionList;

  DBG1("PKCS #11 module = [%s]", module);
  /* reset pkcs #11 handle */
  memset(h, 0, sizeof(pkcs11_handle_t));
  /* check module permissions */
  rv = stat(module, &module_stat);
  if (rv < 0) {
    set_error("stat() failed: %s", strerror(errno));
    return -1;
  }
  DBG3("module permissions: uid = %d, gid = %d, mode = %o",
      module_stat.st_uid, module_stat.st_gid, module_stat.st_mode & 0777);
  if (module_stat.st_mode & S_IWGRP || module_stat.st_mode & S_IWOTH
      || module_stat.st_uid != 0 || module_stat.st_gid != 0) {
    set_error("the pkcs #11 module MUST be owned by root and MUST NOT "
              "be writeable by the group or others");
    return -1;
  }
  /* load module */
  DBG1("loading module %s", module);
  h->module_handle = dlopen(module, RTLD_NOW);
  if (h->module_handle == NULL) {
    set_error("dlopen() failed: %s", dlerror());
    return -1;
  }
  /* try to get the function list */
  DBG("getting function list");
  C_GetFunctionList = (CK_C_GetFunctionList)dlsym(h->module_handle, "C_GetFunctionList");
  if (C_GetFunctionList == NULL) {
    set_error("dlsym() failed: %s", dlerror());
    return -1;
  }
  rv = C_GetFunctionList(&h->fl);
  if (rv != CKR_OK) {
    set_error("C_GetFunctionList() failed: %x", rv);
    return -1;
  }
  return 0;
}

int init_pkcs11_module(pkcs11_handle_t *h)
{
  int rv;
  CK_ULONG i, j;
  CK_SLOT_ID_PTR slots;
  CK_INFO info;

  /* initialise the module */
  rv = h->fl->C_Initialize(NULL);
  if (rv != CKR_OK) {
    set_error("C_Initialize() failed: %x", rv);
    return -1;
  }
  rv = h->fl->C_GetInfo(&info);
  if (rv != CKR_OK) {
    set_error("C_GetInfo() failed: %x", rv);
    return -1;
  }
  /* show some information about the module */
  DBG("module information:");
  DBG2("- version: %hhd.%hhd", info.cryptokiVersion.major, info.cryptokiVersion.minor);
  DBG1("- manufacturer: %.32s", info.manufacturerID);
  DBG1("- flags: %04lx", info.flags);
  DBG1("- library description: %.32s", info.libraryDescription);
  DBG2("- library version: %hhd.%hhd", info.libraryVersion.major, info.libraryVersion.minor);
  /* get a list of all slots */
  rv = h->fl->C_GetSlotList(FALSE, NULL, &h->slot_count);
  if (rv != CKR_OK) {
    set_error("C_GetSlotList() failed: %x", rv);
    return -1;
  }
  DBG1("number of slots (a): %d", h->slot_count);
  if (h->slot_count == 0) {
    set_error("there are no slots available");
    return -1;
  }
  slots = malloc(h->slot_count * sizeof(CK_SLOT_ID));
  if (slots == NULL) {
    set_error("not enough free memory available");
    return -1;
  }
  h->slots = malloc(h->slot_count * sizeof(slot_t));
  if (h->slots == NULL) {
    free(slots);
    set_error("not enough free memory available");
    return -1;
  }
  memset(h->slots, 0, h->slot_count * sizeof(slot_t));
  rv = h->fl->C_GetSlotList(FALSE, slots, &h->slot_count);
  if (rv != CKR_OK) {
    free(slots);
    set_error("C_GetSlotList() failed: %x", rv);
    return -1;
  }
  DBG1("number of slots (b): %d", h->slot_count);
  /* show some information about the slots/tokens and setup slot info */
  for (i = 0; i < h->slot_count; i++) {
    CK_SLOT_INFO sinfo;
    CK_TOKEN_INFO tinfo;

    DBG1("slot %d:", i + 1);
    rv = h->fl->C_GetSlotInfo(slots[i], &sinfo);
    if (rv != CKR_OK) {
      free(slots);
      set_error("C_GetSlotInfo() failed: %x", rv);
      return -1;
    }
    h->slots[i].id = slots[i];
    DBG1("- description: %.64s", sinfo.slotDescription);
    DBG1("- manufacturer: %.32s", sinfo.manufacturerID);
    DBG1("- flags: %04lx", sinfo.flags);
    if (sinfo.flags & CKF_TOKEN_PRESENT) {
      DBG("- token:");
      rv = h->fl->C_GetTokenInfo(slots[i], &tinfo);
      if (rv != CKR_OK) {
        free(slots);
        set_error("C_GetTokenInfo() failed: %x", rv);
        return -1;
      }
      DBG1("  - label: %.32s", tinfo.label);
      DBG1("  - manufacturer: %.32s", tinfo.manufacturerID);
      DBG1("  - model: %.16s", tinfo.model);
      DBG1("  - serial: %.16s", tinfo.serialNumber);
      DBG1("  - flags: %04lx", tinfo.flags);
      h->slots[i].token_present = TRUE;
      memcpy(h->slots[i].label, tinfo.label, 32);
      for (j = 31; h->slots[i].label[j] == ' '; j--) h->slots[i].label[j] = 0;
    }
  }
  free(slots);
  return 0;
}

void release_pkcs11_module(pkcs11_handle_t *h)
{
  /* finalise pkcs #11 module */
  if (h->fl != NULL)
    h->fl->C_Finalize(NULL);
  /* unload the module */
  if (h->module_handle != NULL)
    dlclose(h->module_handle);
  /* release all allocated memory */
  if (h->slots != NULL)
    free(h->slots);
  memset(h, 0, sizeof(pkcs11_handle_t));
}

int open_pkcs11_session(pkcs11_handle_t *h, unsigned int slot)
{
  int rv;

  DBG1("opening a new PKCS #11 session for slot %d", slot + 1);
  if (slot >= h->slot_count) {
    set_error("invalid slot number %d", slot);
    return -1;
  } 
  /* open a readonly user-session */
  rv = h->fl->C_OpenSession(h->slots[slot].id, CKF_SERIAL_SESSION, NULL, NULL, &h->session);
  if (rv != CKR_OK) {
    set_error("C_OpenSession() failed: %x", rv);
    return -1;
  }
  return 0;
}

int pkcs11_login(pkcs11_handle_t *h, char *password)
{
  int rv;

  DBG("login as user CKU_USER");
  rv = h->fl->C_Login(h->session, CKU_USER, (unsigned char*)password, strlen(password));
  if (rv != CKR_OK) {
    set_error("C_Login() failed: %x", rv);
    return -1;
  }
  return 0;
}

int pkcs11_pass_login(pkcs11_handle_t *h, int nullok)
{
  int rv;
  char *pin;

  /* get password */
  pin =getpass("PIN for token: ");
#ifndef DEBUG_HIDE_PASSWORD
  DBG1("PIN = [%s]", pin);
#endif
  /* for safety reasons, clean PIN string from memory asap */

  /* check password length */
  if (!nullok && strlen(pin) == 0) {
    memset(pin, 0, strlen(pin));
    free(pin);
    set_error("Empty passwords not allowed");
    return -1;
  }

  /* perform pkcs #11 login */
  rv = pkcs11_login(h, pin);
  memset(pin, 0, strlen(pin));
  free(pin);
  if (rv != 0) {
    release_pkcs11_module(h);
    /* DBG1("pkcs11_login() failed: %s", get_error()); */
    return -1;
  }
  return 0;
}

int close_pkcs11_session(pkcs11_handle_t *h)
{
  int rv, i;

  /* close user-session */
  DBG("logout user");
  rv = h->fl->C_Logout(h->session);
  if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
    set_error("C_Logout() failed: %x", rv);
    return -1;
  }
  DBG("closing the PKCS #11 session");
  rv = h->fl->C_CloseSession(h->session);
  if (rv != CKR_OK) {
    set_error("C_CloseSession() failed: %x", rv);
    return -1;
  }
  DBG("releasing keys and certificates");
  if (h->keys != NULL) {
    for (i = 0; i < h->key_count; i++) {
      if (h->keys[i].x509 != NULL)
        X509_free(h->keys[i].x509);
      if (h->keys[i].id != NULL)
        free(h->keys[i].id);
    }
    free(h->keys);
    h->keys = NULL;
    h->key_count = 0;
  }
  return 0;
}

int get_certificates(pkcs11_handle_t *h)
{
  CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
  CK_ATTRIBUTE cert_template[] = {
    {CKA_CLASS, &cert_class, sizeof(CK_OBJECT_CLASS)}
    ,
    {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(CK_CERTIFICATE_TYPE)}
    ,
    {CKA_ID, NULL, 0}
    ,
    {CKA_VALUE, NULL, 0}
  };
  CK_BYTE *cert_value;
  CK_OBJECT_HANDLE object;
  CK_ULONG object_count;
  X509 *x509;
  int i, rv;

  /* search for appropriate certificates */
  for (i = 0; i < h->key_count; i++) {
    DBG1("searching certificate for key #%d", i + 1);
    cert_template[2].pValue = h->keys[i].id;
    cert_template[2].ulValueLen = h->keys[i].id_length;
    cert_template[3].pValue = 0;
    cert_template[3].ulValueLen = 0;
    rv = h->fl->C_FindObjectsInit(h->session, cert_template, 3);
    if (rv != CKR_OK) {
      set_error("C_FindObjectsInit() failed: %x", rv);
      return -1;
    }
    rv = h->fl->C_FindObjects(h->session, &object, 1, &object_count);
    if (rv != CKR_OK) {
      set_error("C_FindObjects() failed: %x", rv);
      return -1;
    }
    if (object_count > 0) {
      DBG("X.509 certificate found");
      /* read certificate */
      cert_template[3].pValue = NULL;
      rv = h->fl->C_GetAttributeValue(h->session, object, cert_template, 4);
      if (rv != CKR_OK) {
        set_error("C_GetAttributeValue() failed: %x", rv);
        return -1;
      }
      cert_value = malloc(cert_template[3].ulValueLen);
      if (cert_value == NULL) {
        set_error("not enough free memory available", rv);
        return -1;
      }
      cert_template[3].pValue = cert_value;
      rv = h->fl->C_GetAttributeValue(h->session, object, cert_template, 4);
      if (rv != CKR_OK) {
        free(cert_value);
        set_error("C_GetAttributeValue() failed: %x", rv);
        return -1;
      }
      /* parse certificate */
      x509 = d2i_X509(NULL, (CK_BYTE **)&cert_template[3].pValue, cert_template[3].ulValueLen);
      if (x509 == NULL) {
        free(cert_value);
        set_error("d2i_x509() failed: %s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
      }
      DBG1("saving certificate #%d:", i + 1);
      h->keys[i].x509 = x509;
      DBG1("- subject:    %s", X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0));
      DBG1("- issuer:     %s", X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0));
      DBG1("- algorith:   %s", OBJ_nid2ln(OBJ_obj2nid(x509->cert_info->key->algor->algorithm)));
    }
    rv = h->fl->C_FindObjectsFinal(h->session);
    if (rv != CKR_OK) {
      set_error("C_FindObjectsFinal() failed: %x", rv);
      return -1;
    }
  }
  return 0;
}

int get_private_keys(pkcs11_handle_t *h)
{
  CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
  CK_BBOOL key_sign = CK_TRUE;
  CK_KEY_TYPE key_type = CKK_RSA; /* default, should be properly set */
  CK_ATTRIBUTE key_template[] = {
    {CKA_CLASS, &key_class, sizeof(key_class)}
    ,
    {CKA_SIGN, &key_sign, sizeof(key_sign)}
    ,
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)}
    ,
    {CKA_ID, NULL, 0}
  };
  CK_OBJECT_HANDLE object;
  CK_ULONG object_count;
  CK_BYTE *key_id;
  key_object_t *keys;
  int rv;

  /* search all private keys which can be used to sign */
  rv = h->fl->C_FindObjectsInit(h->session, key_template, 2);
  if (rv != CKR_OK) {
    set_error("C_FindObjectsInit() failed: %x", rv);
    return -1;
  }
  while (1) {
    rv = h->fl->C_FindObjects(h->session, &object, 1, &object_count);
    if (rv != CKR_OK) {
      set_error("C_FindObjects() failed: %x", rv);
      return -1;
    }
    if (object_count == 0)
      break;
    DBG("private key found");
    /* get attribute size */
    key_template[3].pValue = NULL;
    rv = h->fl->C_GetAttributeValue(h->session, object, key_template, 4);
    if (rv != CKR_OK) {
      set_error("C_GetAttributeValue() failed: %x", rv);
      return -1;
    }
    key_id = malloc(key_template[3].ulValueLen);
    if (key_id == NULL) {
      set_error("not enough free memory available");
      return -1;
    }
    key_template[3].pValue = key_id;
    /* get attribute */
    rv = h->fl->C_GetAttributeValue(h->session, object, key_template, 4);
    if (rv != CKR_OK) {
      free(key_id);
      set_error("C_GetAttributeValue() failed: %x", rv);
      return -1;
    }
    keys = realloc(h->keys, (h->key_count + 1) * sizeof(key_object_t));
    if (keys == NULL) {
      free(key_id);
      set_error("not enough free memory available");
      return -1;
    }
    h->keys = keys;
    /* save key */
    DBG1("saving private key #%d:", h->key_count + 1);
    memset(&h->keys[h->key_count], 0, sizeof(key_object_t));
    DBG1("- type: %02x", key_type);
    DBG1("- id:   %02x", key_id[0]);
    h->keys[h->key_count].private_key = object;
    h->keys[h->key_count].type = key_type;
    h->keys[h->key_count].id = key_id;
    h->keys[h->key_count].id_length = key_template[3].ulValueLen;
    ++h->key_count;
  }
  rv = h->fl->C_FindObjectsFinal(h->session);
  if (rv != CKR_OK) {
    set_error("C_FindObjectsFinal() failed: %x", rv);
    return -1;
  }
  /* we need at least one private key */
  if (h->key_count == 0) {
    set_error("no appropiate private keys found");
    return -1;
  }
  return 0;
}

int sign_value(pkcs11_handle_t *h, CK_BYTE *data, CK_ULONG length,
               CK_BYTE **signature, CK_ULONG *signature_length)
{
  int rv;
  CK_BYTE hash[15 + SHA_DIGEST_LENGTH] =
      "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
  CK_MECHANISM mechanism = { 0, NULL, 0 };

  /* set mechanism */
  switch (h->choosen_key->type) {
    case CKK_RSA:
      mechanism.mechanism = CKM_RSA_PKCS;
      break;
    default:
      set_error("unsupported key type %d", h->choosen_key->type);
      return -1;
  }
  /* compute hash-value */
  SHA1(data, length, &hash[15]);
  DBG5("hash[%d] = [...:%02x:%02x:%02x:...:%02x]", sizeof(hash),
      hash[15], hash[16], hash[17], hash[sizeof(hash) - 1]);
  /* sign the token */
  rv = h->fl->C_SignInit(h->session, &mechanism, h->choosen_key->private_key);
  if (rv != CKR_OK) {
    set_error("C_SignInit() failed: %x", rv);
    return -1;
  }
  *signature = NULL;
  *signature_length = 128;
  while (*signature == NULL) {
    *signature = malloc(*signature_length);
    if (*signature == NULL) {
      set_error("not enough free memory available");
      return -1;
    }
    rv = h->fl->C_Sign(h->session, hash, sizeof(hash), *signature, signature_length);
    if (rv == CKR_BUFFER_TOO_SMALL) {
      /* increase signature length as long as it it to short */
      free(*signature);
      *signature = NULL;
      *signature_length *= 2;
      DBG1("increased signature buffer-length to %d", *signature_length);
    } else if (rv != CKR_OK) {
      free(*signature);
      *signature = NULL;
      set_error("C_Sign() failed: %x", rv);
      return -1;
    }
  }
  DBG5("signature[%d] = [%02x:%02x:%02x:...:%02x]", *signature_length,
      (*signature)[0], (*signature)[1], (*signature)[2], (*signature)[*signature_length - 1]);
  return 0;
}

int get_random_value(unsigned char *data, int length)
{
  static const char *random_device = "/dev/urandom";
  int rv, fh, l;

  DBG2("reading %d random bytes from %s", length, random_device);
  fh = open(random_device, O_RDONLY);
  if (fh == -1) {
    set_error("open() failed: %s", strerror(errno));
    return -1;
  }

  l = 0;
  while (l < length) {
    rv = read(fh, data + l, length - l);
    if (rv <= 0) {
      close(fh);
      set_error("read() failed: %s", strerror(errno));
      return -1;
    }
    l += rv;
  }
  close(fh);
  DBG5("random-value[%d] = [%02x:%02x:%02x:...:%02x]", length, data[0],
      data[1], data[2], data[length - 1]);
  return 0;
}
