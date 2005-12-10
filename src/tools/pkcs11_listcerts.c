/*
 * PKCS#11 Card viewer tool
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
 * Based on a previous work of Mario Strasser <mast@gmx.net>,
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/x509.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/rsaref/pkcs11.h"
#include "../common/pkcs11_lib.h"
#include "../common/cert_info.h"
#include "../pam_pkcs11/pam_config.h"
#include "../pam_pkcs11/mapper_mgr.h"

int main(int argc, const char **argv) {
  int i, rv;
  int ncerts;
  unsigned int slot_num = 0;
  struct configuration_st *configuration;
  X509 **cert_list;
  pkcs11_handle_t ph;
  X509 *myCert=NULL;

  /* first of all check whether debugging should be enabled */
  for (i = 0; i < argc; i++)
    if (strcmp("debug", argv[i]) == 0) {
      set_debug_level(1);
    }

  /* call configure routines */
  configuration = pk_configure(argc,argv);
  if (!configuration ) {
	DBG("Error setting configuration parameters");
	return 1;
  }

  /* init openssl */
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  /* load pkcs #11 module */
  DBG("loading pkcs #11 module...");
  rv = load_pkcs11_module(configuration->pkcs11_modulepath, &ph);
  if (rv != 0) {
    DBG1("load_pkcs11_module() failed: %s", get_error());
    return 1;
  }

  /* initialise pkcs #11 module */
  DBG("initialising pkcs #11 module...");
  rv = init_pkcs11_module(&ph);
  if (rv != 0) {
    release_pkcs11_module(&ph);
    DBG1("init_pkcs11_module() failed: %s", get_error());
    return 1;
  }

  /* open pkcs #11 session */
  slot_num= configuration->slot_num;
  if (slot_num == 0) {
    DBG("using the first slot with an available token");
    for (slot_num = 0; slot_num < ph.slot_count && !ph.slots[slot_num].token_present; slot_num++);
    if (slot_num >= ph.slot_count) {
      release_pkcs11_module(&ph);
      DBG("no token available");
      return 1;
    }
  } else {
    slot_num--;
  }
  rv = open_pkcs11_session(&ph, slot_num);
  if (rv != 0) {
    release_pkcs11_module(&ph);
    DBG1("open_pkcs11_session() failed: %s", get_error());
    return 1;
  }

  /* get certificate list */
  ncerts=0;
  cert_list=NULL;
  cert_list = get_certificate_list(&ph,&ncerts);
  if (!cert_list) {
    close_pkcs11_session(&ph);
    release_pkcs11_module(&ph);
    DBG1("get_certificate_list() failed: %s", get_error());
    return 3;
  }
  /* print some info on found certificates */
  DBG1("Found '%d' certificate(s)",ncerts);
  for(i =0; i<ncerts;i++) {
    X509 *cert=cert_list[i];
    rv = verify_certificate(cert,&configuration->policy);
    if (rv < 0) {
        DBG1("verify_certificate() process error: %s", get_error());
        goto auth_failed;
    } else if (rv != 1) {
        DBG1("verify_certificate() failed: %s", get_error());
        continue; /* try next certificate */
    }
    myCert=cert;
    DBG1("Certificate #%d:", i);
    DBG1("- Subject:   %s", X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
    DBG1("- Issuer:    %s", X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0));
    DBG1("- Algorithm: %s", OBJ_nid2ln(OBJ_obj2nid(cert->cert_info->key->algor->algorithm)));
  }

  if (configuration->policy.signature_policy) {
    rv = pkcs11_pass_login(&ph,configuration->nullok);
    if (rv != 0) {
      DBG1("pkcs11_pass_login() failed: %s", get_error());
      free(cert_list);
      close_pkcs11_session(&ph);
      release_pkcs11_module(&ph);
      return 2;
    }
    rv = get_private_keys(&ph);
    if (rv != 0) {
      DBG1("get_private_keys() failed: %s", get_error());
      goto auth_failed;
    }
    /* load corresponding certificates */
    rv = get_certificates(&ph);
    if (rv != 0) {
      DBG1("get_certificates() failed: %s", get_error());
      goto auth_failed;
    }
    ph.choosen_key= NULL;
    for (i=0; i< ph.key_count; i++)  {
	if (!ph.keys[i].x509) continue;
        X509 *cert= ph.keys[i].x509;
        if (X509_cmp(cert,myCert) == 0) ph.choosen_key = &ph.keys[i];
    }
    if (!ph.choosen_key) {
      DBG("Cannot locate private key matching successfull cert");
      goto auth_failed;
    }
  }

  free(cert_list);

  /* close pkcs #11 session */
  rv = close_pkcs11_session(&ph);
  if (rv != 0) {
    release_pkcs11_module(&ph);
    DBG1("close_pkcs11_session() failed: %s", get_error());
    return 4;
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(&ph);

  DBG("Process completed");
  return 0;

auth_failed:
  free(cert_list);
  close_pkcs11_session(&ph);
  release_pkcs11_module(&ph);
  return 5;

}
