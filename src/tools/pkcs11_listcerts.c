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
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/pkcs11_lib.h"
#include "../common/cert_info.h"
#include "../pam_pkcs11/pam_config.h"
#include "../pam_pkcs11/mapper_mgr.h"

int main(int argc, const char **argv) {
  int i, rv;
  int ncerts;
  unsigned int slot_num = 0;
  struct configuration_st *configuration;
  pkcs11_handle_t *ph;
  cert_object_t **certs;

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

  if ((configuration->slot_description != NULL && configuration->slot_num != -1) || (configuration->slot_description == NULL && configuration->slot_num == -1)) {
	ERR("Error setting configuration parameters");
	return 1;
  }

  /* init openssl */
  rv = crypto_init(&configuration->policy);
  if (rv != 0) {
    DBG("Couldn't initialize crypto module ");
    return 1;
  }

  /* load pkcs #11 module */
  DBG("loading pkcs #11 module...");
  rv = load_pkcs11_module(configuration->pkcs11_modulepath, &ph);
  if (rv != 0) {
    DBG1("load_pkcs11_module() failed: %s", get_error());
    return 1;
  }

  /* initialise pkcs #11 module */
  DBG("initialising pkcs #11 module...");
  rv = init_pkcs11_module(ph,configuration->support_threads);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG1("init_pkcs11_module() failed: %s", get_error());
    return 1;
  }

  /* open pkcs #11 session */
  if (configuration->slot_description != NULL) {
    rv = find_slot_by_slotlabel(ph,configuration->slot_description, &slot_num);
  } else {
    rv = find_slot_by_number(ph,configuration->slot_num, &slot_num);
  }

  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG("no token available");
    return 1;
  }

  rv = open_pkcs11_session(ph, slot_num);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG1("open_pkcs11_session() failed: %s", get_error());
    return 1;
  }

  /* do login */
  rv = pkcs11_pass_login(ph,configuration->nullok);
  if (rv<0){
    DBG1("Login failed: %s",get_error());
    return 4;
  }

  /* get certificate list */
  certs = get_certificate_list(ph, &ncerts);
  if (certs == NULL) {
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    DBG1("get_certificates() failed: %s", get_error());
    return 3;
  }

  /* print some info on found certificates */
  DBG1("Found '%d' certificate(s)", ncerts);
  for(i =0; i< ncerts;i++) {
    char **name;
    X509 *cert=get_X509_certificate(certs[i]);

    DBG1("Certificate #%d:", i+1);
    name = cert_info(cert, CERT_SUBJECT, ALGORITHM_NULL);
    DBG1("- Subject:   %s", name[0]); free(name[0]);
    name = cert_info(cert, CERT_ISSUER, ALGORITHM_NULL);
    DBG1("- Issuer:    %s", name[0]); free(name[0]);
    name = cert_info(cert, CERT_KEY_ALG, ALGORITHM_NULL);
    DBG1("- Algorithm: %s", name[0]); free(name[0]);
    rv = verify_certificate(cert,&configuration->policy);
    if (rv < 0) {
        DBG1("verify_certificate() process error: %s", get_error());
        goto auth_failed;
    } else if (rv != 1) {
        DBG1("verify_certificate() failed: %s", get_error());
        continue; /* try next certificate */
    }
    rv = get_private_key(ph, certs[i]);
    if (rv<0) {
	DBG1("Certificate '%d'does not have associated private key",i+1);
    }
  } /* for */

  /* close pkcs #11 session */
  rv = close_pkcs11_session(ph);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG1("close_pkcs11_session() failed: %s", get_error());
    return 4;
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(ph);

  DBG("Process completed");
  return 0;

auth_failed:
  close_pkcs11_session(ph);
  release_pkcs11_module(ph);
  return 5;

}
