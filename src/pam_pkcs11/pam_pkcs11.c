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
	char *pt = (char *) str;
	if (!str)
		return 1;
	if (!strcmp(str, ""))
		return 1;
	for (; *pt; pt++)
		if (!isspace(*pt))
			return 0;
	return 1;
}

#ifndef HAVE_SECURITY_PAM_EXT_H
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
	rv = pam_get_item(pamh, PAM_CONV, &conv);
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
	memset(resp[0].resp, 0, strlen(resp[0].resp));
	free(&resp[0]);
	return PAM_SUCCESS;
}

static void
pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(priority, fmt, ap);
	va_end(ap);
}
#endif

/*
 * Gets the users password. Depending whether it was already asked, either
 * a prompt is shown or the old value is returned.
 */
static int pam_get_pwd(pam_handle_t *pamh, char **pwd, char *text, int oitem,
		int nitem) {
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
		rv = pam_get_item(pamh, oitem, (void*)&old_pwd);
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
		rv = pam_get_item(pamh, PAM_CONV, (void*)&conv);
		if (rv != PAM_SUCCESS)
			return rv;
		if ((conv == NULL) || (conv->conv == NULL))
			return PAM_CRED_INSUFFICIENT;
		rv = conv->conv(1, msgp, &resp, conv->appdata_ptr);
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
			rv = pam_set_item(pamh, nitem, *pwd);
			if (rv != PAM_SUCCESS)
				return rv;
		}
		return PAM_SUCCESS;
	}
	return PAM_CRED_INSUFFICIENT;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	int i, rv;
	unsigned long int _slot; 		//BE!!: added _slot for scan
	unsigned long int _slot_count;  //BE!!: added for scan max available slots
	const char *user = NULL;
	char *password;
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
	char env_temp[1024] = "";
	char **issuer, **serial;
	const char *login_token_name = NULL;


	/* first of all check whether debugging should be enabled */
	for (i = 0; i < argc; i++)
		if (strcmp("debug", argv[i]) == 0) {
			set_debug_level(1);
		}

	/* call configure routines */
	configuration = pk_configure(argc, argv);
	if (!configuration) {
		ERR("Error setting configuration parameters");
		return PAM_AUTHINFO_UNAVAIL;
	}

	if (!is_a_screen_saver && !configuration->quiet)
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("SmartCard authentication starts"));

	/* Either slot_description or slot_num, but not both, needs to be used.
	BE!!: High skilled usabillity: Therefore we search the SmartCard
	if ((configuration->slot_description != NULL
			&& configuration->slot_num != -1)
			|| (configuration->slot_description == NULL
					&& configuration->slot_num == -1)) {
		ERR("Error setting configuration parameters");
		return PAM_AUTHINFO_UNAVAIL;
	}
	*/

	/* fail if we are using a remote server
	 * local login: DISPLAY=:0
	 * XDMCP login: DISPLAY=host:0 */
	{
		char *display = getenv("DISPLAY");

		if (display) {
			if (strncmp(display, "localhost:", 10) != 0 && (display[0] != ':')
					&& (display[0] != '\0')) {
				ERR1("Remote login (from %s) is not (yet) supported", display);
				pam_syslog(pamh, LOG_ERR,
						"Remote login (from %s) is not (yet) supported",
						display);
				return PAM_AUTHINFO_UNAVAIL;
			}
		}
	}

#ifdef ENABLE_NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, "/usr/share/locale");
	textdomain(PACKAGE);
#endif

	/* init openssl */
	rv = crypto_init(&configuration->policy);
	if (rv != 0) {
		ERR("Failed to initialize crypto");
		if (!configuration->quiet)
			pam_syslog(pamh, LOG_ERR, "Failed to initialize crypto");
		return PAM_AUTHINFO_UNAVAIL;
	}

	/*
	 * card_only means:
	 *  1) always get the userid from the certificate.
	 *  2) don't prompt for the user name if the card is present.
	 *  3) if the token is present, then we must use the cardAuth mechanism.
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
		DBG("Using card_only mode...");
		char *service;
		if (configuration->screen_savers) {
			DBG("Is it a screen saver?");
			pam_get_item(pamh, PAM_SERVICE, (void*)&service);
			for (i = 0; configuration->screen_savers[i]; i++) {
				if (strcmp(configuration->screen_savers[i], service) == 0) {
					is_a_screen_saver = 1;
					break;
				}
			}
		}

		pkcs11_pam_fail = PAM_CRED_INSUFFICIENT;

		/* look to see if username is already set */
		pam_get_item(pamh, PAM_USER, (void*)&user);
		if (user) {
			DBG1("explicit username = [%s]", user);
		}
	} else {
		rv = pam_get_item(pamh, PAM_USER, (void*)&user);
		if (rv != PAM_SUCCESS || user == NULL || user[0] == '\0') {
			pam_prompt(pamh, PAM_TEXT_INFO, NULL,
					_("Please insert your %s or enter your username."),
					_(configuration->token_type));
			/* get user name */
			rv = pam_get_user(pamh, &user, NULL);
			if (rv != PAM_SUCCESS) {
				pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s",
						pam_strerror(pamh, rv));
				return PAM_USER_UNKNOWN;
			}
		}
		DBG1("username = [%s]", user);
	}

	login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");

	/* if we are using a screen saver, and we didn't log in using the SmartCard
	 * drop to the next pam module.  */
	if (is_a_screen_saver && !login_token_name) {
		DBG("Screen_saver active without login token name, skip pkcs#11 module...");
		return PAM_IGNORE;
	}

	/* load pkcs #11 module */
	DBG("loading pkcs #11 module...");
	rv = load_pkcs11_module(configuration->pkcs11_modulepath, &ph);
	if (rv != 0) {
		ERR2("load_pkcs11_module() failed loading %s: %s",
				configuration->pkcs11_modulepath, get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR,
					"load_pkcs11_module() failed loading %s: %s",
					configuration->pkcs11_modulepath, get_error());
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2302: PKCS#11 module failed loading"));
			sleep(configuration->err_display_time);
		}
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* initialise pkcs #11 module */
	DBG("initialising pkcs #11 module...");
	rv = init_pkcs11_module(ph, configuration->support_threads);
	if (rv != 0) {
		release_pkcs11_module(ph);
		ERR1("init_pkcs11_module() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "init_pkcs11_module() failed: %s",
					get_error());
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2304: PKCS#11 module could not be initialized"));
			sleep(configuration->err_display_time);
		}
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* open pkcs #11 session */
	if (configuration->slot_description != NULL) {
		rv = find_slot_by_slotlabel_and_tokenlabel(ph,
				configuration->slot_description, login_token_name, &slot_num);
	}
	else if (configuration->slot_num != -1) {
		rv = find_slot_by_number_and_label(ph, configuration->slot_num,
				login_token_name, &slot_num);
	}
	//BE!!: Scan available slots
	else {
		_slot_count = get_slot_count(ph);
		for(_slot = 0; _slot < _slot_count; _slot++) {
			rv = find_slot_by_number_and_label(ph, _slot,
					login_token_name, &slot_num);
			if (rv == 0 && slot_num != -1) {
				DBG1("Slot auto scan found SmartCard in slot %d", slot_num);
				configuration->slot_num = slot_num;
				break;
			}
		}
		// pkcs11 breaks standard - nothing found!?
		if (configuration->slot_num == -1) {
			ERR("No suitable slot can be found! Please configure a SmartCard slot.");
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "no suitable token available");
				pam_prompt(pamh, PAM_ERROR_MSG, NULL,
						_("Error 2306a: No suitable slot can be found! Please configure a SmartCard slot."));
				sleep(configuration->err_display_time);
			}
			return PAM_AUTHINFO_UNAVAIL;
		}
	}

	if (rv != 0) {
		ERR("no suitable token available");
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "no suitable token available");
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2306: No suitable token available"));
			sleep(configuration->err_display_time);
		}

		if (!configuration->card_only) {
			release_pkcs11_module(ph);
			return PAM_AUTHINFO_UNAVAIL;
		}

		/* we must have a SmartCard, either because we've configured it as such,
		 * or because we used one to log in */
		if (login_token_name || configuration->wait_for_card) {
			if (login_token_name) {
				pam_prompt(pamh, PAM_TEXT_INFO, NULL,
						_("Please insert your SmartCard called \"%.32s\"."),
						login_token_name);
			} else {
				pam_prompt(pamh, PAM_TEXT_INFO, NULL,
						_("Please insert your SmartCard."));
			}

			if (configuration->slot_description != NULL) {
				rv = wait_for_token_by_slotlabel(ph,
						configuration->slot_description, login_token_name,
						&slot_num);
			} else if (configuration->slot_num != -1) {
				rv = wait_for_token(ph, configuration->slot_num,
						login_token_name, &slot_num);
			}

			if (rv != 0) {
				release_pkcs11_module(ph);
				return pkcs11_pam_fail;
			}
		} else if (user) {
			if (!configuration->quiet) {
				pam_prompt(pamh, PAM_ERROR_MSG, NULL,
						_("Error 2308: No SmartCard found"));
				sleep(configuration->err_display_time);
			}

			/* we have a user and no SmartCard, go to the next pam module */
			release_pkcs11_module(ph);
			return PAM_AUTHINFO_UNAVAIL;
		} else {
			/* we haven't prompted for the user yet, get the user and see if
			 * the SmartCard has been inserted in the mean time */
			pam_prompt(pamh, PAM_TEXT_INFO, NULL,
					_("Please insert your %s or enter your username."),
					_(configuration->token_type));
			rv = pam_get_user(pamh, &user, NULL);

			/* check one last time for the SmartCard before bouncing to the next
			 * module */
			if (configuration->slot_description != NULL) {
				rv = find_slot_by_slotlabel(ph, configuration->slot_description,
						&slot_num);
			} else if (configuration->slot_num != -1) {
				rv = find_slot_by_number(ph, configuration->slot_num,
						&slot_num);
			}

			if (rv != 0) {
				/* user gave us a user id and no SmartCard go to next module */
				if (!configuration->quiet) {
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2310: No SmartCard found"));
					sleep(configuration->err_display_time);
				}

				release_pkcs11_module(ph);
				return PAM_AUTHINFO_UNAVAIL;
			}
		}
	} else {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("%s found."),
				_(configuration->token_type));
	}
	rv = open_pkcs11_session(ph, slot_num);
	if (rv != 0) {
		ERR1("open_pkcs11_session() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "open_pkcs11_session() failed: %s",
					get_error());
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2312: open PKCS#11 session failed"));
			sleep(configuration->err_display_time);
		}
		release_pkcs11_module(ph);
		return pkcs11_pam_fail;
	}

	rv = get_slot_login_required(ph);
	if (rv == -1) {
		ERR1("get_slot_login_required() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "get_slot_login_required() failed: %s",
					get_error());
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2314: Slot login failed"));
			sleep(configuration->err_display_time);
		}
		release_pkcs11_module(ph);
		return pkcs11_pam_fail;
	} else if (rv) {
		/* get password */
		if (!is_a_screen_saver)
			pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("Welcome %.32s!"),
						get_slot_tokenlabel(ph));

		/* no CKF_PROTECTED_AUTHENTICATION_PATH */
		rv = get_slot_protected_authentication_path(ph);
		if ((-1 == rv) || (0 == rv)) {
			char password_prompt[128];

			snprintf(password_prompt, sizeof(password_prompt), _("%s PIN: "),
					_(configuration->token_type));
			if (configuration->use_first_pass) {
				rv = pam_get_pwd(pamh, &password, NULL, PAM_AUTHTOK, 0);
			} else if (configuration->try_first_pass) {
				rv = pam_get_pwd(pamh, &password, password_prompt, PAM_AUTHTOK,
						PAM_AUTHTOK);
			} else {
				rv = pam_get_pwd(pamh, &password, password_prompt, 0,
						PAM_AUTHTOK);
			}
			if (rv != PAM_SUCCESS) {
				if (!configuration->quiet) {
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2316: password could not be read"));
					sleep(configuration->err_display_time);
				}
				release_pkcs11_module(ph);
				pam_syslog(pamh, LOG_ERR, "pam_get_pwd() failed: %s",
						pam_strerror(pamh, rv));
				return pkcs11_pam_fail;
			}
#ifdef DEBUG_SHOW_PASSWORD
			DBG1("password = [%s]", password);
#endif

			/* check password length */
			if (!configuration->nullok && strlen(password) == 0) {
				release_pkcs11_module(ph);
				memset(password, 0, strlen(password));
				free(password);
				pam_syslog(pamh, LOG_ERR,
						"password length is zero but the 'nullok' argument was not defined.");
				if (!configuration->quiet) {
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2318: Empty SmartCard PIN not allowed."));
					sleep(configuration->err_display_time);
				}
				return PAM_AUTH_ERR;
			}
		} else {
			pam_prompt(pamh, PAM_TEXT_INFO, NULL,
					_("Enter your %s PIN on the pinpad"),
					_(configuration->token_type));
			/* use pin pad */
			password = NULL;
		}

		/* call pkcs#11 login to ensure that the user is the real owner of the card
		 * we need to do thise before get_certificate_list because some tokens
		 * can not read their certificates until the token is authenticated */
		rv = pkcs11_login(ph, password);
		/* erase and free in-memory password data asap */
		if (password) {
			memset(password, 0, strlen(password));
			free(password);
		}
		if (rv != 0) {
			ERR1("open_pkcs11_login() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "open_pkcs11_login() failed: %s",
						get_error());
				pam_prompt(pamh, PAM_ERROR_MSG, NULL,
						_("Error 2320: Wrong SmartCard PIN"));
				sleep(configuration->err_display_time);
			}
			goto auth_failed_nopw;
		}
	}

	cert_list = get_certificate_list(ph, &ncert);
	if (rv < 0) {
		ERR1("get_certificate_list() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "get_certificate_list() failed: %s",
					get_error());
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2322: No certificate found"));
			sleep(configuration->err_display_time);
		}
		goto auth_failed_nopw;
	}

	/* load mapper modules */
	load_mappers(configuration->ctx);

	/* find a valid and matching certificates */
	for (i = 0; i < ncert; i++) {
		X509 *x509 = (X509 *) get_X509_certificate(cert_list[i]);
		if (!x509)
			continue; /* sanity check */
		DBG1("verifying the certificate #%d", i + 1);
		if (!is_a_screen_saver && !configuration->quiet) {
			pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("verifying certificate"));
		}

		/* verify certificate (date, signature, CRL, ...) */
		rv = verify_certificate(x509, &configuration->policy);
		if (rv < 0) {
			ERR1("verify_certificate() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "verify_certificate() failed: %s",
						get_error());
				switch (rv) {
				case -2: // X509_V_ERR_CERT_HAS_EXPIRED:
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2324: Certificate has expired"));
					break;
				case -3: // X509_V_ERR_CERT_NOT_YET_VALID:
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2326: Certificate not yet valid"));
					break;
				case -4: // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2328: Certificate signature invalid"));
					break;
				default:
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
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

		if (is_spaced_str(user) || strlen(user) == 0) {
			/*
			 if provided user is null or empty extract and set user
			 name from certificate
			 */
			DBG("Empty login: try to deduce from certificate");
			user = find_user(x509);
			if (!user) {
				ERR2("find_user() failed: %s on cert #%d", get_error(), i + 1);
				if (!configuration->quiet)
					pam_syslog(pamh, LOG_ERR,
							"find_user() failed: %s on cert #%d", get_error(),
							i + 1);
				continue; /* try on next certificate */
			} else {
				DBG1("certificate is valid and matches user %s", user);
				/* try to set up PAM user entry with evaluated value */
				rv = pam_set_item(pamh, PAM_USER, (const void *) user);
				if (rv != PAM_SUCCESS) {
					ERR1("pam_set_item() failed %s", pam_strerror(pamh, rv));
					if (!configuration->quiet) {
						pam_syslog(pamh, LOG_ERR, "pam_set_item() failed %s",
								pam_strerror(pamh, rv));
						pam_prompt(pamh, PAM_ERROR_MSG, NULL,
								_("Error 2332: setting PAM userentry failed"));
						sleep(configuration->err_display_time);
					}
					goto auth_failed_nopw;
				}
				snprintf(env_temp, sizeof(env_temp) - 1, "USER=%.*s",
							(int) ((sizeof(env_temp) - 1) - strlen("USER=")),
							user);
				rv = pam_putenv(pamh, env_temp);
				if (rv != PAM_SUCCESS) {
					if (!configuration->quiet) {
						pam_syslog(pamh, LOG_ERR, "pam_putenv() failed %s",
								pam_strerror(pamh, rv));
						pam_prompt(pamh, PAM_ERROR_MSG, NULL,
								_("Error 2332: setting PAM userentry failed"));
						sleep(configuration->err_display_time);
					}
					goto auth_failed_nopw;
				}
				DBG1("PAM user item has been set to user '%s'", user);
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
					pam_syslog(pamh, LOG_ERR, "match_user() failed: %s",
							get_error());
					pam_prompt(pamh, PAM_ERROR_MSG, NULL,
							_("Error 2334: No matching user"));
					sleep(configuration->err_display_time);
				}
				goto auth_failed_nopw;
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
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					_("Error 2336: No matching certificate found"));
			sleep(configuration->err_display_time);
		}
		goto auth_failed_nopw;
	}

	/* if signature check is enforced, generate random data, sign and verify */
	if (!is_a_screen_saver && !configuration->quiet &&
			configuration->policy.signature_policy) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("Checking signature"));

#ifdef notdef
		rv = get_private_key(ph);
		if (rv != 0) {
			ERR1("get_private_key() failed: %s", get_error());
			if (!configuration->quiet)
			pam_syslog(pamh, LOG_ERR,
					"get_private_key() failed: %s", get_error());
			goto auth_failed_nopw;
		}
#endif

		/* read random value */
		rv = get_random_value(random_value, sizeof(random_value));
		if (rv != 0) {
			ERR1("get_random_value() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "get_random_value() failed: %s",
						get_error());
				pam_prompt(pamh, PAM_ERROR_MSG, NULL,
						_("Error 2338: Getting random value failed"));
				sleep(configuration->err_display_time);
			}
			goto auth_failed_nopw;
		}

		/* sign random value */
		signature = NULL;
		rv = sign_value(ph, chosen_cert, random_value, sizeof(random_value),
				&signature, &signature_length);
		if (rv != 0) {
			ERR1("sign_value() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "sign_value() failed: %s",
						get_error());
				pam_prompt(pamh, PAM_ERROR_MSG, NULL,
						_("Error 2340: Signing failed"));
				sleep(configuration->err_display_time);
			}
			goto auth_failed_nopw;
		}

		/* verify the signature */
		DBG("verifying signature...");
		rv = verify_signature((X509 *) get_X509_certificate(chosen_cert),
				random_value, sizeof(random_value), signature,
				signature_length);
		if (signature != NULL) {
			free(signature);
		}
		if (rv != 0) {
			close_pkcs11_session(ph);
			release_pkcs11_module(ph);
			ERR1("verify_signature() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "verify_signature() failed: %s",
						get_error());
				pam_prompt(pamh, PAM_ERROR_MSG, NULL,
						_("Error 2342: Verifying signature failed"));
				sleep(configuration->err_display_time);
			}
			return PAM_AUTH_ERR;
		}

	} else {
		DBG("Skipping signature check");
	}

	/*
	 * fill in the environment variables.
	 */
	snprintf(env_temp, sizeof(env_temp) - 1, "PKCS11_LOGIN_TOKEN_NAME=%.*s",
			(int) ((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_TOKEN_NAME=")),
			get_slot_tokenlabel(ph));
	rv = pam_putenv(pamh, env_temp);

	if (rv != PAM_SUCCESS) {
		ERR1("could not put token name in environment: %s",
				pam_strerror(pamh, rv));
		if (!configuration->quiet)
			pam_syslog(pamh, LOG_ERR,
					"could not put token name in environment: %s",
					pam_strerror(pamh, rv));
	}

	issuer = cert_info((X509 *) get_X509_certificate(chosen_cert), CERT_ISSUER,
			ALGORITHM_NULL);
	if (issuer) {
		snprintf(env_temp, sizeof(env_temp) - 1,
				"PKCS11_LOGIN_CERT_ISSUER=%.*s",
				(int) ((sizeof(env_temp) - 1)
						- strlen("PKCS11_LOGIN_CERT_ISSUER=")), issuer[0]);
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
			pam_syslog(pamh, LOG_ERR,
					"could not put cert issuer in environment: %s",
					pam_strerror(pamh, rv));
	}

	serial = cert_info((X509 *) get_X509_certificate(chosen_cert), CERT_SERIAL,
			ALGORITHM_NULL);
	if (serial) {
		snprintf(env_temp, sizeof(env_temp) - 1,
				"PKCS11_LOGIN_CERT_SERIAL=%.*s",
				(int) ((sizeof(env_temp) - 1)
						- strlen("PKCS11_LOGIN_CERT_SERIAL=")), serial[0]);
		rv = pam_putenv(pamh, env_temp);
	} else {
		ERR("couldn't get certificate serial number.");
		if (!configuration->quiet)
			pam_syslog(pamh, LOG_ERR,
					"couldn't get certificate serial number.");
	}

	if (rv != PAM_SUCCESS) {
		ERR1("could not put cert serial in environment: %s",
				pam_strerror(pamh, rv));
		if (!configuration->quiet)
			pam_syslog(pamh, LOG_ERR,
					"could not put cert serial in environment: %s",
					pam_strerror(pamh, rv));
	}

	/* unload mapper modules */
	unload_mappers();

	/* close pkcs #11 session */
	rv = close_pkcs11_session(ph);
	if (rv != 0) {
		release_pkcs11_module(ph);
		ERR1("close_pkcs11_session() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "close_pkcs11_module() failed: %s",
					get_error());
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
					("Error 2344: Closing PKCS#11 session failed"));
			sleep(configuration->err_display_time);
		}
		return pkcs11_pam_fail;
	}

	/* release pkcs #11 module */
	DBG("releasing pkcs #11 module...");
	release_pkcs11_module(ph);

	DBG("authentication succeeded");
	return PAM_SUCCESS;

	/* quick and dirty fail exit point */
	memset(password, 0, strlen(password));
	free(password); /* erase and free in-memory password data */

	auth_failed_nopw: unload_mappers();
	close_pkcs11_session(ph);
	release_pkcs11_module(ph);
	return pkcs11_pam_fail;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	DBG("pam_sm_setcred() called");
	/* Actually, we should return the same value as pam_sm_authenticate(). */
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	ERR(
			"Warning: Function pm_sm_acct_mgmt() is not implemented in this module");
	pam_syslog(pamh, LOG_WARNING,
			"Function pm_sm_acct_mgmt() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	ERR(
			"Warning: Function pam_sm_open_session() is not implemented in this module");
	pam_syslog(pamh, LOG_WARNING,
			"Function pm_sm_open_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	ERR(
			"Warning: Function pam_sm_close_session() is not implemented in this module");
	pam_syslog(pamh, LOG_WARNING,
			"Function pm_sm_close_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	char *login_token_name;

	ERR(
			"Warning: Function pam_sm_chauthtok() is not implemented in this module");
	pam_syslog(pamh, LOG_WARNING,
			"Function pam_sm_chauthtok() is not implemented in this module");

	login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");
	if (login_token_name && (flags & PAM_PRELIM_CHECK)) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL,
				_("Cannot change the password on your SmartCard."));
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
