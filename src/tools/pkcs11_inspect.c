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
#include "../common/cert_vfy.h"
#include "../pam_pkcs11/pam_config.h"
#include "../pam_pkcs11/mapper_mgr.h"

int main(int argc, const char **argv) {
  int i, rv;
  pkcs11_handle_t *ph;
  struct configuration_st *configuration;
  unsigned int slot_num = 0;
  cert_object_t **certs;
  int cert_count;

  /* first of all check whether debugging should be enabled */
  for (i = 0; i < argc; i++)
    if (strcmp("debug", argv[i]) == 0) {
      set_debug_level(1);
    }

  /* call configure routines */
  configuration = pk_configure(argc,argv);
  if (!configuration ) {
	ERR("Error setting configuration parameters");
	return 1;
  }

  /* init openssl */
  rv = crypto_init(&configuration->policy);
  if (rv != 0) {
    DBG1("crypto_init() failed: %s", get_error());
    return 1;
  }

  /* load pkcs #11 module */
  DBG("loading pkcs #11 module...");
  rv = load_pkcs11_module(configuration->pkcs11_modulepath, &ph);
  if (rv != 0) {
    ERR2("load_pkcs11_module(%s) failed: %s", configuration->pkcs11_modulepath,
      get_error());
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
  rv = find_slot_by_number(ph, configuration->slot_num, &slot_num);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG("no token available");
    return 1;
  }

  rv = open_pkcs11_session(ph, slot_num);
  if (rv != 0) {
    release_pkcs11_module(ph);
    ERR1("open_pkcs11_session() failed: %s", get_error());
    return 1;
  }

#if HAVE_NSS
  /* not really needed, but.... */
  rv = pkcs11_pass_login(ph,configuration->nullok);
  if (rv != 0) {
    ERR1("pkcs11_pass_login() failed: %s", get_error());
    return 2;
  }
#endif

  /* get certificate list (cert space is owned by ph) */
  certs = get_certificate_list(ph, &cert_count);
  if (certs == NULL) {
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    ERR1("get_certificates() failed: %s", get_error());
    return 3;
  }

  /* load mapper modules */
  load_mappers(configuration->ctx);

  /* find valid certificates and look for contents */
  DBG1("Found '%d' certificate(s)", cert_count);
  for (i = 0; i < cert_count; i++) {
    X509 *x509 = get_X509_certificate(certs[i]);
    if (x509 != NULL) {
      DBG1("verifing the certificate #%d", i + 1);
      /* verify certificate (date, signature, CRL, ...) */
      rv = verify_certificate(x509, &configuration->policy);
      if (rv < 0) {
        close_pkcs11_session(ph);
        release_pkcs11_module(ph);
	unload_mappers();
        ERR1("verify_certificate() failed: %s", get_error());
        return 1;
      } else if (rv != 1) {
        ERR1("verify_certificate() failed: %s", get_error());
        continue;
      }

      DBG1("Inspecting certificate #%d",i+1);
      inspect_certificate(x509);
    }
  }

  /* unload mappers */
  unload_mappers();

  /* close pkcs #11 session */
  rv = close_pkcs11_session(ph);
  if (rv != 0) {
    release_pkcs11_module(ph);
    ERR1("close_pkcs11_session() failed: %s", get_error());
    return 1;
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(ph);

  DBG("Process completed");
  return 0;
}
