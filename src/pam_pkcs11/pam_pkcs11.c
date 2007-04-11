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

/* We have to make this definitions before we include the pam header files! */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/pkcs11_lib.h"
#include "../common/cert_vfy.h"
#include "../common/cert_st.h"
#include "pam_config.h"
#include "mapper_mgr.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif
#define LOGNAME   "PAM-PKCS11"  /* name for log-file entries */

/*
* comodity function that returns 1 on null, empty o spaced string
*/
int is_spaced_str(const char *str) {
	char *pt=(char *)str;
	if(!str) return 1;
	if (!strcmp(str,"")) return 1;
	for (;*pt;pt++) if (!isspace(*pt)) return 0;
	return 1;
}

/*
 * Gets the users password. Depending whether it was already asked, either
 * a prompt is shown or the old value is returned.
 */
static int pam_get_pwd(pam_handle_t *pamh, char **pwd, char *text, int oitem, int nitem)
{
  int rv;
  const char *old_pwd;
  struct pam_conv *conv;
  struct pam_message msg;
  struct pam_response *resp;
  /* struct pam_message *(msgp[1]) = { &msg}; */
  struct pam_message *(msgp[1]);
  msgp[0] = &msg;

  /* use stored password if variable oitem is set */
  if ((oitem == PAM_AUTHTOK) || (oitem == PAM_OLDAUTHTOK)) {
    /* try to get stored item */
    rv = pam_get_item(pamh, oitem, (const void **) &old_pwd);
    if (rv != PAM_SUCCESS)
      return rv;
    if (old_pwd != NULL) {
      *pwd = strdup(old_pwd);
      return PAM_SUCCESS;
    }
  }

  /* ask the user for the password if variable text is set */
  if (text != NULL) {
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = text;
    rv = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (rv != PAM_SUCCESS)
      return rv;
    if ((conv == NULL) || (conv->conv == NULL))
      return PAM_CRED_INSUFFICIENT;
    rv = conv->conv(1, (const struct pam_message **)msgp, &resp, conv->appdata_ptr);
    if (rv != PAM_SUCCESS)
      return rv;
    if ((resp == NULL) || (resp[0].resp == NULL))
      return PAM_CRED_INSUFFICIENT;
    *pwd = strdup(resp[0].resp);
    /* overwrite memory and release it */
    memset(resp[0].resp, 0, strlen(resp[0].resp));
    free(&resp[0]);
    /* save password if variable nitem is set */
    if ((nitem == PAM_AUTHTOK) || (nitem == PAM_OLDAUTHTOK)) {
      rv = pam_set_item(pamh, nitem, pwd);
      if (rv != PAM_SUCCESS)
        return rv;
    }
    return PAM_SUCCESS;
  }
  return PAM_CRED_INSUFFICIENT;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int i, rv;
  const char *user;
  char *password;
  char password_prompt[64];
  unsigned int slot_num = 0;
  struct configuration_st *configuration;

  pkcs11_handle_t *ph;
  cert_object_t *chosen_cert = NULL;
  cert_object_t **cert_list;
  int ncert;
  unsigned char random_value[128];
  unsigned char *signature;
  unsigned long signature_length;

  /* first of all check whether debugging should be enabled */
  for (i = 0; i < argc; i++)
    if (strcmp("debug", argv[i]) == 0) {
      set_debug_level(1);
    }

  /* call configure routines */
  configuration = pk_configure(argc,argv);
  if (!configuration ) {
	DBG("Error setting configuration parameters");
	return PAM_AUTHINFO_UNAVAIL;
  }
  /* open log */
  openlog(LOGNAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);

  /* fail if we are using a remote server
   * local login: DISPLAY=:0
   * XDMCP login: DISPLAY=host:0 */
  {
	  char *display = getenv("DISPLAY");

	  if (display && (display[0] != ':') && (display[0] != '\0'))
	  {
		syslog(LOG_ERR, "Remote login (from %s) is not (yet) supported",
			getenv("DISPLAY"));
		return PAM_AUTHINFO_UNAVAIL;
	  }
  }
  
  /* init openssl */
  rv = crypto_init(&configuration->policy);
  if (rv != 0) {
    DBG("Failed to initialize crypto");
    syslog(LOG_ERR, "Failed to initialize crypto");
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* get user name */
  rv = pam_get_user(pamh, &user, NULL);
  if (rv != PAM_SUCCESS) {
    syslog(LOG_ERR, "pam_get_user() failed %s", pam_strerror(pamh, rv));
    return PAM_USER_UNKNOWN;
  }
  DBG1("username = [%s]", user);

  /* load pkcs #11 module */
  DBG("loading pkcs #11 module...");
  rv = load_pkcs11_module(configuration->pkcs11_modulepath, &ph);
  if (rv != 0) {
    DBG1("load_pkcs11_module() failed: %s", get_error());
    syslog(LOG_ERR, "load_pkcs11_module() failed: %s", get_error());
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* initialise pkcs #11 module */
  DBG("initialising pkcs #11 module...");
  rv = init_pkcs11_module(ph,configuration->support_threads);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG1("init_pkcs11_module() failed: %s", get_error());
    syslog(LOG_ERR, "init_pkcs11_module() failed: %s", get_error());
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* open pkcs #11 session */
  rv = find_slot_by_number(ph, configuration->slot_num, &slot_num);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG("no token available");
    syslog(LOG_ERR, "no token available");
    return PAM_AUTHINFO_UNAVAIL;
  }
  rv = open_pkcs11_session(ph, slot_num);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG1("open_pkcs11_session() failed: %s", get_error());
    syslog(LOG_ERR, "open_pkcs11_session() failed: %s", get_error());
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* get password */
  sprintf(password_prompt, "PIN for token %.32s: ", get_slot_label(ph));
  if (configuration->use_first_pass) {
    rv = pam_get_pwd(pamh, &password, NULL, PAM_AUTHTOK, 0);
  } else if (configuration->try_first_pass) {
    rv = pam_get_pwd(pamh, &password, password_prompt, PAM_AUTHTOK, PAM_AUTHTOK);
  } else {
    rv = pam_get_pwd(pamh, &password, password_prompt, 0, PAM_AUTHTOK);
  }
  if (rv != PAM_SUCCESS) {
    release_pkcs11_module(ph);
    syslog(LOG_ERR, "pam_get_pwd() failed: %s", pam_strerror(pamh, rv));
    return PAM_AUTHINFO_UNAVAIL;
  }
#ifndef DEBUG_HIDE_PASSWORD
  DBG1("password = [%s]", password);
#endif

  /* check password length */
  if (!configuration->nullok && strlen(password) == 0) {
    release_pkcs11_module(ph);
    memset(password, 0, strlen(password));
    free(password);
    syslog(LOG_ERR, "password length is zero but the 'nullok' argument was not defined.");
    return PAM_AUTH_ERR;
  }

  /* call pkcs#11 login to ensure that the user is the real owner of the card 
   * we need to do thise before get_certificate_list because some tokens
   * can not read their certificates until the token is authenticated */
  rv = pkcs11_login(ph, password);
  /* erase and free in-memory password data asap */
  memset(password, 0, strlen(password));
  free(password); 
  if (rv != 0) {
    DBG1("open_pkcs11_login() failed: %s", get_error());
    syslog(LOG_ERR, "open_pkcs11_login() failed: %s", get_error());
    goto auth_failed_nopw;
  }

  cert_list = get_certificate_list(ph, &ncert);
  if (rv<0) {
    DBG1("get_certificate_list() failed: %s", get_error());
    syslog(LOG_ERR, "get_certificate_list() failed: %s", get_error());
    goto auth_failed_nopw;
  }

  /* load mapper modules */
  load_mappers(configuration->ctx);

  /* find a valid and matching certificates */
  for (i = 0; i < ncert; i++) {
    X509 *x509 = get_X509_certificate(cert_list[i]);
    if (!x509 ) continue; /* sanity check */
    DBG1("verifing the certificate #%d", i + 1);

      /* verify certificate (date, signature, CRL, ...) */
      rv = verify_certificate(x509,&configuration->policy);
      if (rv < 0) {
        DBG1("verify_certificate() failed: %s", get_error());
        syslog(LOG_ERR, "verify_certificate() failed: %s", get_error());
	goto auth_failed_nopw;
      } else if (rv != 1) {
        DBG1("verify_certificate() failed: %s", get_error());
        continue; /* try next certificate */
      }

    /* CA and CRL verified, now check/find user */

    if ( is_spaced_str(user) ) {
      /* 
	if provided user is null or empty extract and set user
	name from certificate
      */
	DBG("Empty login: try to deduce from certificate");
	user=find_user(x509);
	if (!user) {
          DBG2("find_user() failed: %s on cert #%d", get_error(),i+1);
          syslog(LOG_ERR,"find_user() failed: %s on cert #%d",get_error(),i+1);
	  continue; /* try on next certificate */
	} else {
          DBG1("certificate is valid and matches user %s",user);
	  /* try to set up PAM user entry with evaluated value */
  	  rv = pam_set_item(pamh, PAM_USER,(const void *)user);
	  if (rv != PAM_SUCCESS) {
	    DBG1("pam_set_item() failed %s", pam_strerror(pamh, rv));
	    syslog(LOG_ERR, "pam_set_item() failed %s", pam_strerror(pamh, rv));
	    goto auth_failed_nopw;
	}
          chosen_cert = cert_list[i];
          break; /* end loop, as find user success */
      }
    } else {
      /* User provided:
         check whether the certificate matches the user */
        rv = match_user(x509, user);
        if (rv < 0) { /* match error; abort and return */
          DBG1("match_user() failed: %s", get_error());
          syslog(LOG_ERR, "match_user() failed: %s", get_error());
	  goto auth_failed_nopw;
        } else if (rv == 0) { /* match didn't success */
          DBG("certificate is valid bus does not match the user");
	  continue; /* try next certificate */
        } else { /* match success */
          DBG("certificate is valid and matches the user");
          chosen_cert = cert_list[i];
          break;
      }
    } /* if is_spaced string */
  } /* for (i=0; i<ncerts; i++) */

  /* now myCert points to our found certificate or null if no user found */
  if (!chosen_cert) {
    DBG("no valid certificate which meets all requirements found");
    syslog(LOG_ERR, "no valid certificate which meets all requirements found");
    goto auth_failed_nopw;
  }


  /* if signature check is enforced, generate random data, sign and verify */
  if (configuration->policy.signature_policy) {

#ifdef notdef
    rv = get_private_key(ph);
    if (rv != 0) {
      DBG1("get_private_key() failed: %s", get_error());
      syslog(LOG_ERR, "get_private_key() failed: %s", get_error());
      goto auth_failed_nopw;
    }
#endif

    /* read random value */
    rv = get_random_value(random_value, sizeof(random_value));
    if (rv != 0) {
      DBG1("get_random_value() failed: %s", get_error());
      syslog(LOG_ERR, "get_random_value() failed: %s", get_error());
      goto auth_failed_nopw;
    }

    /* sign random value */
    signature = NULL;
    rv = sign_value(ph, chosen_cert, random_value, sizeof(random_value), 
		    &signature, &signature_length);
    if (rv != 0) {
      DBG1("sign_value() failed: %s", get_error());
      syslog(LOG_ERR, "sign_value() failed: %s", get_error());
      goto auth_failed_nopw;
    }

    /* verify the signature */
    DBG("verifying signature...");
    rv = verify_signature(get_X509_certificate(chosen_cert),
             random_value, sizeof(random_value), signature, signature_length);
    if (signature != NULL) free(signature);
    if (rv != 0) {
      close_pkcs11_session(ph);
      release_pkcs11_module(ph);
      DBG1("verify_signature() failed: %s", get_error());
      syslog(LOG_ERR, "verify_signature() failed: %s", get_error());
      return PAM_AUTH_ERR;
    }

  } else {
      DBG("Skipping signature check");
  }

  /* close pkcs #11 session */
  rv = close_pkcs11_session(ph);
  if (rv != 0) {
    release_pkcs11_module(ph);
    DBG1("close_pkcs11_session() failed: %s", get_error());
    syslog(LOG_ERR, "close_pkcs11_module() failed: %s", get_error());
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(ph);

  DBG("authentication succeeded");
  return PAM_SUCCESS;

    /* quick and dirty fail exit point */
    memset(password, 0, strlen(password));
    free(password); /* erase and free in-memory password data */

auth_failed_nopw:
    unload_mappers();
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    return PAM_AUTHINFO_UNAVAIL;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("pam_sm_setcred() called");
  /* Actually, we should return the same value as pam_sm_authenticate(). */
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("Warning: Function pm_sm_acct_mgmt() is not implemented in this module");
  openlog(LOGNAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  syslog(LOG_WARNING, "Function pm_sm_acct_mgmt() is not implemented in this module");
  closelog();
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("Warning: Function pam_sm_open_session() is not implemented in this module");
  openlog(LOGNAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  syslog(LOG_WARNING, "Function pm_sm_open_session() is not implemented in this module");
  closelog();
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("Warning: Function pam_sm_close_session() is not implemented in this module");
  openlog(LOGNAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  syslog(LOG_WARNING, "Function pm_sm_close_session() is not implemented in this module");
  closelog();
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("Warning: Function pam_sm_chauthtok() is not implemented in this module");
  openlog(LOGNAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  syslog(LOG_WARNING, "Function pam_sm_chauthtok() is not implemented in this module");
  closelog();
  return PAM_SERVICE_ERR;
}

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_group_modstruct = {
  "pam_pkcs11",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};
#endif
