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
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif
/* OpenPAM used on *BSD and OS X */
#ifdef OPENPAM
#include <security/openpam.h>
#endif
#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/pkcs11_lib.h"
#include "../common/cert_vfy.h"
#include "../common/cert_info.h"
#include "../common/cert_st.h"
#include "pam_config.h"
#include "mapper_mgr.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(string) gettext(string)
#else
#define _(string) string
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif
#define LOGNAME   "PAM-PKCS11"  /* name for log-file entries */

/*
* comodity function that returns 1 on null, empty o spaced string
*/
static int is_spaced_str(const char *str) {
	char *pt=(char *)str;
	if(!str) return 1;
	if (!strcmp(str,"")) return 1;
	for (;*pt;pt++) if (!isspace(*pt)) return 0;
	return 1;
}

#if !defined(HAVE_SECURITY_PAM_EXT_H) && !defined(OPENPAM)
/*
 * implement pam utilities for older versions of pam.
 */
static int pam_prompt(pam_handle_t *pamh, int style, char **response, char *fmt, ...)
{
  int rv;
  struct pam_conv *conv;
  struct pam_message msg;
  struct pam_response *resp;
  /* struct pam_message *(msgp[1]) = { &msg}; */
  struct pam_message *(msgp[1]);
  msgp[0] = &msg;
  va_list va;
  char text[128];

  va_start(va, fmt);
  vsnprintf(text, sizeof text, fmt, va);
  va_end(va);

  msg.msg_style = style;
  msg.msg = text;
  rv = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
  if (rv != PAM_SUCCESS)
    return rv;
  if ((conv == NULL) || (conv->conv == NULL))
    return PAM_CRED_INSUFFICIENT;
  rv = conv->conv(1, msgp, &resp, conv->appdata_ptr);
  if (rv != PAM_SUCCESS)
    return rv;
  if ((resp == NULL) || (resp[0].resp == NULL))
    return !response ? PAM_SUCCESS : PAM_CRED_INSUFFICIENT;
  if (response) {
     *response = strdup(resp[0].resp);
  }
  /* overwrite memory and release it */
  cleanse(resp[0].resp, strlen(resp[0].resp));
  free(&resp[0]);
  return PAM_SUCCESS;
}
#endif

#if !defined(HAVE_SECURITY_PAM_EXT_H) || defined(OPENPAM)
static void
pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);
}

/*
 * With OpenPAM pam_prompt resp arg cannot be NULL, so this is just a wrapper.
 */
#undef pam_prompt
#define pam_prompt(x, y, z, fmt, ...) pam_pkcs11_prompt((x), (y), (z), (fmt), ##__VA_ARGS__)

static int pam_pkcs11_prompt(const pam_handle_t *pamh, int style, char **resp, const char *fmt, ...)
{
  char *response = NULL;
  va_list va;
  int ret = 0;

  va_start(va, fmt);
  ret = pam_vprompt(pamh, style, &response, fmt, va);
  va_end(va);

  free(response);

  return ret;
}
#endif


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
  const struct pam_message *(msgp[1]);
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
    rv = conv->conv(1, msgp, &resp, conv->appdata_ptr);
    if (rv != PAM_SUCCESS) goto pwd_exit;
    if ((resp == NULL) || (resp[0].resp == NULL)) {
      rv = PAM_CRED_INSUFFICIENT;
      goto pwd_exit;
    }
    *pwd = strdup(resp[0].resp);
    /* overwrite memory and release it */
    cleanse(resp[0].resp, strlen(resp[0].resp));
    free(resp[0].resp);
    free(&resp[0]);
    /* save password if variable nitem is set */
    if ((nitem == PAM_AUTHTOK) || (nitem == PAM_OLDAUTHTOK)) {
      rv = pam_set_item(pamh, nitem, *pwd);
      if (rv != PAM_SUCCESS)
        return rv;
    }
    return PAM_SUCCESS;
  }
pwd_exit:
  if(NULL != resp[0].resp) {
    cleanse(resp[0].resp, strlen(resp[0].resp));
    free(resp[0].resp);
  }
  if(NULL != &resp[0]) {
    free(&resp[0]);
  }
  return rv;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int i, rv;
  char *user = NULL;
  char *password = NULL;
  unsigned int slot_num = 0;
  int is_a_screen_saver = 0;
  struct configuration_st *configuration;
  int pkcs11_pam_fail = PAM_AUTHINFO_UNAVAIL;

  pkcs11_handle_t *ph;
  cert_object_t *chosen_cert = NULL;
  cert_object_t **cert_list;
  int ncert;
  unsigned char random_value[128];
  unsigned char *signature;
  unsigned long signature_length;
  /* enough space to hold an issuer DN */
  char env_temp[256] = "";
  char **issuer, **serial;
  const char *login_token_name = NULL;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, "/usr/share/locale");
  textdomain(PACKAGE);
#endif

  /* first of all check whether debugging should be enabled */
  for (i = 0; i < argc; i++)
    if (strcmp("debug", argv[i]) == 0) {
      set_debug_level(1);
    }

  /* call configure routines */
  configuration = pk_configure(argc,argv);
  if (!configuration ) {
	ERR("Error setting configuration parameters");
	return PAM_AUTHINFO_UNAVAIL;
  }

  /* Either slot_description or slot_num, but not both, needs to be used */
  if ((configuration->slot_description != NULL && configuration->slot_num != -1) || (configuration->slot_description == NULL && configuration->slot_num == -1)) {
	ERR("Error setting configuration parameters");
       configure_free(configuration);
	return PAM_AUTHINFO_UNAVAIL;
  }

  login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");
  /*
   * card_only means: restrict the authentication to token only if
   * the user has already authenticated by the token.
   *
   * wait_for_card means:
   *  1) nothing if card_only isn't set
   *  2) if logged in, block in pam conversation until the token used for login
   *     is inserted
   *  3) if not logged in, block until a token that could be used for logging in
   *     is inserted
   * right now, logged in means PKC11_LOGIN_TOKEN_NAME is set,
   * but we could something else later (like set some per-user state in
   * a pam session module keyed off uid)
   */
  if (configuration->card_only) {
	char *service;
	if (configuration->screen_savers) {
	    DBG("Is it a screen saver?");
		pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
	    for (i=0; configuration->screen_savers[i]; i++) {
		if (strcmp(configuration->screen_savers[i], service) == 0) {
		    is_a_screen_saver = 1;
		    break;
		}
	    }
	}
  }

  if (!configuration->card_only || !login_token_name) {
	  /* Allow to pass to the next module if the auth isn't
         restricted to card only. */
      pkcs11_pam_fail = PAM_IGNORE;
  } else {
	pkcs11_pam_fail = PAM_CRED_INSUFFICIENT;
  }

  /* fail if we are using a remote server
   * local login: DISPLAY=:0
   * XDMCP login: DISPLAY=host:0 */
  {
	  char *display = getenv("DISPLAY");

	  if (display)
	  {
		  if (strncmp(display, "localhost:", 10) != 0 && (display[0] != ':')
			  && (display[0] != '\0')) {
			  ERR1("Remote login (from %s) is not (yet) supported", display);
			  pam_syslog(pamh, LOG_ERR,
				  "Remote login (from %s) is not (yet) supported", display);
                         configure_free(configuration);
			  return pkcs11_pam_fail;
		  }
	  }
  }
  /* init openssl */
  rv = crypto_init(&configuration->policy);
  if (rv != 0) {
    ERR("Failed to initialize crypto");
    if (!configuration->quiet)
      pam_syslog(pamh,LOG_ERR, "Failed to initialize crypto");
    configure_free(configuration);
    return pkcs11_pam_fail;
  }
  
  /* look to see if username is already set */
  pam_get_item(pamh, PAM_USER, (const void **) &user);
  if (user) {
      DBG1("explicit username = [%s]", user);
  }
  
  /* if we are using a screen saver, and we didn't log in using the smart card
   * drop to the next pam module.  */
  if (is_a_screen_saver && !login_token_name) {
	  goto exit_ignore;
  }

  /* load pkcs #11 module */
  DBG("loading pkcs #11 module...");
  rv = load_pkcs11_module(configuration->pkcs11_modulepath, &ph);
  if (rv != 0) {
    ERR2("load_pkcs11_module() failed loading %s: %s",
		configuration->pkcs11_modulepath, get_error());
    if (!configuration->quiet) {
		pam_syslog(pamh, LOG_ERR, "load_pkcs11_module() failed loading %s: %s",
			configuration->pkcs11_modulepath, get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2302: PKCS#11 module failed loading"));
		sleep(configuration->err_display_time);
	}
    configure_free(configuration);
    return pkcs11_pam_fail;
  }  

  /* initialise pkcs #11 module */
  DBG("initialising pkcs #11 module...");
  rv = init_pkcs11_module(ph,configuration->support_threads);
  if (rv != 0) {
    release_pkcs11_module(ph);
    ERR1("init_pkcs11_module() failed: %s", get_error());
    if (!configuration->quiet) {
		pam_syslog(pamh, LOG_ERR, "init_pkcs11_module() failed: %s", get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2304: PKCS#11 module could not be initialized"));
		sleep(configuration->err_display_time);
	}
    configure_free(configuration);
    return pkcs11_pam_fail;
  }

  if (configuration->slot_description != NULL) {
    rv = find_slot_by_slotlabel_and_tokenlabel(ph,
      configuration->slot_description, login_token_name, &slot_num);
  } else if (configuration->slot_num != -1) {
    rv = find_slot_by_number_and_label(ph, configuration->slot_num,
                                     login_token_name, &slot_num);
  }

  if (rv != 0) {
      /* No token found */
    if (!configuration->card_only) {
        /* If the login isn't restricted to card-only, then proceed
           to the next auth. module quietly. */
        release_pkcs11_module(ph);
        goto exit_ignore;
    }

    ERR("no suitable token available");
    if (!configuration->quiet) {
        pam_syslog(pamh, LOG_ERR, "no suitable token available");
    }

    if (configuration->wait_for_card) {
        if (login_token_name) {
            pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                       _("Please insert your smart card called \"%.32s\"."),
                       login_token_name);
        } else {
            pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                       _("Please insert your smart card."));
        }

        if (configuration->slot_description != NULL) {
            rv = wait_for_token_by_slotlabel(ph, configuration->slot_description,
                                           login_token_name, &slot_num);
        } else if (configuration->slot_num != -1) {
            rv = wait_for_token(ph, configuration->slot_num,
                                login_token_name, &slot_num);
        }
    }
  }

  if (rv != 0) {
      release_pkcs11_module(ph);
      /* Still no card */
      if (pkcs11_pam_fail != PAM_IGNORE) {
          if (!configuration->quiet) {
              pam_prompt(pamh, PAM_ERROR_MSG,
                         NULL, _("Error 2308: No smartcard found"));
              sleep(configuration->err_display_time);
          }
      } else {
          pam_prompt(pamh, PAM_TEXT_INFO,
                     NULL, _("No smartcard found"));
          goto exit_ignore;
      }
      return pkcs11_pam_fail;
  }

  pam_prompt(pamh, PAM_TEXT_INFO, NULL,
             _("%s found."), _(configuration->token_type));

  /* open pkcs #11 session */
  rv = open_pkcs11_session(ph, slot_num);
  if (rv != 0) {
    ERR1("open_pkcs11_session() failed: %s", get_error());
    if (!configuration->quiet) {
		pam_syslog(pamh, LOG_ERR, "open_pkcs11_session() failed: %s", get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2312: open PKCS#11 session failed"));
		sleep(configuration->err_display_time);
	}
    release_pkcs11_module(ph);
    configure_free(configuration);
    return pkcs11_pam_fail;
  }

  rv = get_slot_login_required(ph);
  if (rv == -1) {
    ERR1("get_slot_login_required() failed: %s", get_error());
    if (!configuration->quiet) {
		pam_syslog(pamh, LOG_ERR, "get_slot_login_required() failed: %s", get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2314: Slot login failed"));
		sleep(configuration->err_display_time);
	}
    goto auth_failed;
  } else if (rv) {
    /* get password */
	pam_prompt(pamh, PAM_TEXT_INFO, NULL,
		_("Welcome %.32s!"), get_slot_tokenlabel(ph));

	/* no CKF_PROTECTED_AUTHENTICATION_PATH */
	rv = get_slot_protected_authentication_path(ph);
	if ((-1 == rv) || (0 == rv))
	{
		char password_prompt[128];

		snprintf(password_prompt,  sizeof(password_prompt), _("%s PIN: "), _(configuration->token_type));
		if (configuration->use_first_pass) {
			rv = pam_get_pwd(pamh, &password, NULL, PAM_AUTHTOK, 0);
		} else if (configuration->try_first_pass) {
			rv = pam_get_pwd(pamh, &password, password_prompt, PAM_AUTHTOK,
					PAM_AUTHTOK);
		} else {
			rv = pam_get_pwd(pamh, &password, password_prompt, 0, PAM_AUTHTOK);
		}
		if (rv != PAM_SUCCESS) {
			if (!configuration->quiet) {
				pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2316: password could not be read"));
				sleep(configuration->err_display_time);
			}
			pam_syslog(pamh, LOG_ERR,
					"pam_get_pwd() failed: %s", pam_strerror(pamh, rv));
			goto auth_failed;
		}
#ifdef DEBUG_SHOW_PASSWORD
		DBG1("password = [%s]", password);
#endif

		/* check password length */
		if (!configuration->nullok && strlen(password) == 0) {
			pam_syslog(pamh, LOG_ERR,
					"password length is zero but the 'nullok' argument was not defined.");
			if (!configuration->quiet) {
				pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2318: Empty smartcard PIN not allowed."));
				sleep(configuration->err_display_time);
			}
			pkcs11_pam_fail = PAM_AUTH_ERR;
			goto auth_failed;
		}
	}
	else
	{
		pam_prompt(pamh, PAM_TEXT_INFO, NULL,
			_("Enter your %s PIN on the pinpad"), _(configuration->token_type));
		/* use pin pad */
		password = NULL;
	}

    /* call pkcs#11 login to ensure that the user is the real owner of the card
     * we need to do this before get_certificate_list because some tokens
     * can not read their certificates until the token is authenticated */
    rv = pkcs11_login(ph, password);

    if (rv != 0) {
      ERR1("open_pkcs11_login() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "open_pkcs11_login() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2320: Wrong smartcard PIN"));
			sleep(configuration->err_display_time);
		}
      pkcs11_pam_fail = PAM_AUTH_ERR;
      goto auth_failed;
    }
  }

  cert_list = get_certificate_list(ph, &ncert);
  if (rv<0) {
    ERR1("get_certificate_list() failed: %s", get_error());
    if (!configuration->quiet) {
		pam_syslog(pamh, LOG_ERR, "get_certificate_list() failed: %s", get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2322: No certificate found"));
		sleep(configuration->err_display_time);
	}
    goto auth_failed;
  }

  /* load mapper modules */
  load_mappers(configuration->ctx);

  /* find a valid and matching certificates */
  for (i = 0; i < ncert; i++) {
    X509 *x509 = (X509 *)get_X509_certificate(cert_list[i]);
    if (!x509 ) continue; /* sanity check */
    DBG1("verifying the certificate #%d", i + 1);
	if (!configuration->quiet) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("verifying certificate"));
	}

      /* verify certificate (date, signature, CRL, ...) */
      rv = verify_certificate(x509,&configuration->policy);
      if (rv < 0) {
        ERR1("verify_certificate() failed: %s", get_error());
        if (!configuration->quiet) {
          pam_syslog(pamh, LOG_ERR,
                   "verify_certificate() failed: %s", get_error());
			switch (rv) {
				case -2: // X509_V_ERR_CERT_HAS_EXPIRED:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2324: Certificate has expired"));
					break;
				case -3: // X509_V_ERR_CERT_NOT_YET_VALID:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2326: Certificate not yet valid"));
					break;
				case -4: // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2328: Certificate signature invalid"));
					break;
				default:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2330: Certificate invalid"));
					break;
			}
			sleep(configuration->err_display_time);
		}
        continue; /* try next certificate */
      } else if (rv != 1) {
        ERR1("verify_certificate() failed: %s", get_error());
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
          ERR2("find_user() failed: %s on cert #%d", get_error(),i+1);
          if (!configuration->quiet)
            pam_syslog(pamh, LOG_ERR,
                     "find_user() failed: %s on cert #%d",get_error(),i+1);
	  continue; /* try on next certificate */
	} else {
          DBG1("certificate is valid and matches user %s",user);
	  /* try to set up PAM user entry with evaluated value */
	  rv = pam_set_item(pamh, PAM_USER,(const void *)user);
         free( user );
         user = NULL;
	  if (rv != PAM_SUCCESS) {
	    ERR1("pam_set_item() failed %s", pam_strerror(pamh, rv));
            if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR,
                       "pam_set_item() failed %s", pam_strerror(pamh, rv));
				pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2332: setting PAM userentry failed"));
				sleep(configuration->err_display_time);
			}
	    goto auth_failed;
	}
          chosen_cert = cert_list[i];
          break; /* end loop, as find user success */
      }
    } else {
      /* User provided:
         check whether the certificate matches the user */
        rv = match_user(x509, user);
        if (rv < 0) { /* match error; abort and return */
          ERR1("match_user() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "match_user() failed: %s", get_error());
				pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2334: No matching user"));
				sleep(configuration->err_display_time);
			}
	  goto auth_failed;
        } else if (rv == 0) { /* match didn't success */
          DBG("certificate is valid but does not match the user");
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
    ERR("no valid certificate which meets all requirements found");
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR,
				"no valid certificate which meets all requirements found");
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2336: No matching certificate found"));
		sleep(configuration->err_display_time);
	}
    goto auth_failed;
  }


  /* if signature check is enforced, generate random data, sign and verify */
  if (configuration->policy.signature_policy) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("Checking signature"));


#ifdef notdef
    rv = get_private_key(ph);
    if (rv != 0) {
      ERR1("get_private_key() failed: %s", get_error());
      if (!configuration->quiet)
        pam_syslog(pamh, LOG_ERR,
                 "get_private_key() failed: %s", get_error());
      goto auth_failed;
    }
#endif

    /* read random value */
    rv = get_random_value(random_value, sizeof(random_value));
    if (rv != 0) {
      ERR1("get_random_value() failed: %s", get_error());
		if (!configuration->quiet){
			pam_syslog(pamh, LOG_ERR, "get_random_value() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2338: Getting random value failed"));
			sleep(configuration->err_display_time);
		}
      goto auth_failed;
    }

    /* sign random value */
    signature = NULL;
    rv = sign_value(ph, chosen_cert, random_value, sizeof(random_value),
		    &signature, &signature_length);
    if (rv != 0) {
      ERR1("sign_value() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "sign_value() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2340: Signing failed"));
			sleep(configuration->err_display_time);
		}
      goto auth_failed;
    }

    /* verify the signature */
    DBG("verifying signature...");
    rv = verify_signature((X509 *)get_X509_certificate(chosen_cert),
             random_value, sizeof(random_value), &signature, &signature_length);
    if (signature != NULL) {
      free(signature);
    }
    if (rv != 0) {
      ERR1("verify_signature() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "verify_signature() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2342: Verifying signature failed"));
			sleep(configuration->err_display_time);
		}
      pkcs11_pam_fail = PAM_AUTH_ERR;
      goto auth_failed;
    }

  } else {
      DBG("Skipping signature check");
  }

  /*
   * fill in the environment variables.
   */
  snprintf(env_temp, sizeof(env_temp) - 1,
	   "PKCS11_LOGIN_TOKEN_NAME=%.*s",
	   (int)((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_TOKEN_NAME=") -1),
	   get_slot_tokenlabel(ph));
  rv = pam_putenv(pamh, env_temp);

  if (rv != PAM_SUCCESS) {
    ERR1("could not put token name in environment: %s",
         pam_strerror(pamh, rv));
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "could not put token name in environment: %s",
           pam_strerror(pamh, rv));
  }

  issuer = cert_info((X509 *)get_X509_certificate(chosen_cert), CERT_ISSUER,
                     ALGORITHM_NULL);
  if (issuer) {
    snprintf(env_temp, sizeof(env_temp) - 1,
	   "PKCS11_LOGIN_CERT_ISSUER=%.*s",
	   (int)((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_CERT_ISSUER=") -1),
	   issuer[0]);
    rv = pam_putenv(pamh, env_temp);
  } else {
    ERR("couldn't get certificate issuer.");
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "couldn't get certificate issuer.");
  }

  if (rv != PAM_SUCCESS) {
    ERR1("could not put cert issuer in environment: %s",
         pam_strerror(pamh, rv));
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "could not put cert issuer in environment: %s",
           pam_strerror(pamh, rv));
  }

  serial = cert_info((X509 *)get_X509_certificate(chosen_cert), CERT_SERIAL,
                     ALGORITHM_NULL);
  if (serial) {
    snprintf(env_temp, sizeof(env_temp) - 1,
	   "PKCS11_LOGIN_CERT_SERIAL=%.*s",
	   (int)((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_CERT_SERIAL=") -1),
	   serial[0]);
    rv = pam_putenv(pamh, env_temp);
  } else {
    ERR("couldn't get certificate serial number.");
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "couldn't get certificate serial number.");
  }

  if (rv != PAM_SUCCESS) {
    ERR1("could not put cert serial in environment: %s",
         pam_strerror(pamh, rv));
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "could not put cert serial in environment: %s",
           pam_strerror(pamh, rv));
  }

  /* unload mapper modules */
  unload_mappers();

  /* close pkcs #11 session */
  rv = close_pkcs11_session(ph);
  if (rv != 0) {
    ERR1("close_pkcs11_session() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "close_pkcs11_module() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, ("Error 2344: Closing PKCS#11 session failed"));
			sleep(configuration->err_display_time);
		}
		pkcs11_pam_fail = PAM_AUTH_ERR;
		goto auth_failed;
  }

  if ( password ) {
      cleanse( password, strlen(password) );
      free( password );
      password = NULL;
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(ph);

  DBG("authentication succeeded");
  configure_free(configuration);
  configuration = NULL;    
  return PAM_SUCCESS;

auth_failed:

    unload_mappers();
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    if ( password ) {
        cleanse( password, strlen(password) );
        free( password );
    }
    configure_free(configuration);
    configuration = NULL;
	if (PAM_IGNORE == pkcs11_pam_fail)
		goto exit_ignore;
	else
		return pkcs11_pam_fail;

 exit_ignore:
	pam_prompt( pamh, PAM_TEXT_INFO, NULL,
				_("Smartcard authentication cancelled") );
       configure_free(configuration);
       configuration = NULL;
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("pam_sm_setcred() called");
  /* Actually, we should return the same value as pam_sm_authenticate(). */
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pm_sm_acct_mgmt() is not implemented in this module");
  pam_syslog(pamh, LOG_WARNING,
             "Function pm_sm_acct_mgmt() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pam_sm_open_session() is not implemented in this module");
  pam_syslog(pamh, LOG_WARNING,
             "Function pm_sm_open_session() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pam_sm_close_session() is not implemented in this module");
  pam_syslog(pamh, LOG_WARNING,
           "Function pm_sm_close_session() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char *login_token_name;

  ERR("Warning: Function pam_sm_chauthtok() is not implemented in this module");
  pam_syslog(pamh, LOG_WARNING,
             "Function pam_sm_chauthtok() is not implemented in this module");

  login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");
  if (login_token_name && (flags & PAM_PRELIM_CHECK)) {
    pam_prompt(pamh, PAM_TEXT_INFO, NULL,
               _("Cannot change the password on your smart card."));
  }
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
