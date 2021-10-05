/*
    Generate events on card status change
    Copyrigt (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "config.h"
#include "../scconf/scconf.h"
#include "../common/pkcs11_lib.h"
#include "../common/debug.h"
#include "../common/error.h"

#ifdef HAVE_NSS
#include <secmod.h>
#include <nss.h>
#include <pk11pub.h>
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

#define DEF_POLLING 1			/* 1 second timeout */
#define DEF_EXPIRE 0			/* no expire */
#define DEF_PKCS11_MODULE "/usr/lib/opensc-pkcs11.so"
#define DEF_CONFIG_FILE CONFDIR "/pkcs11_eventmgr.conf"

#define ONERROR_IGNORE	0
#define ONERROR_RETURN	1
#define ONERROR_QUIT	2

#define CARD_PRESENT 1
#define CARD_NOT_PRESENT 0
#define CARD_ERROR -1

int polling_time;
int expire_time;
int daemonize;
int debug;
const char *cfgfile;
char *pkcs11_module = NULL;
#ifdef HAVE_NSS
char *nss_dir = NULL;
#endif

scconf_context *ctx;
const scconf_block *root;

#ifdef HAVE_NSS
SECMODModule *module;
#else
#include "../common/rsaref/pkcs11.h"
pkcs11_handle_t *ph;

typedef struct slot_st slot_t;

/* The direct calls should be abstracted, for now "expose" the pkcs11_handle_t */
struct pkcs11_handle_str
{
	void *module_handle;
	CK_FUNCTION_LIST_PTR fl;
	int should_finalize;
	slot_t *slots;
	CK_ULONG slot_count;
	CK_SESSION_HANDLE session;
	cert_object_t *keys;
	int key_count;
	int current_slot;
};

#endif

static void thats_all_folks(void)
{
	int rv;
	DBG("Exiting");
#ifdef HAVE_NSS
	if (module)
	{
		SECMOD_DestroyModule(module);
	}
	rv = NSS_Shutdown();
	if (rv != SECSuccess)
	{
		DBG("NSS Shutdown failed");
		return;
	}
#else
	/* close pkcs #11 session */
	rv = close_pkcs11_session(ph);
	if (rv != 0)
	{
		release_pkcs11_module(ph);
		DBG1("close_pkcs11_session() failed: %s", get_error());
		return;
	}

	/* release pkcs #11 module */
	DBG("releasing pkcs #11 module...");
	release_pkcs11_module(ph);
#endif
	return;
}

extern char **environ;
static int my_system(char *command)
{
	int pid, status;

	if (!command)
		return 1;

	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0)
	{
		char *argv[4];
		argv[0] = "/bin/sh";
		argv[1] = "-c";
		argv[2] = command;
		argv[3] = 0;
		execve("/bin/sh", argv, environ);
		exit(127);
	}
	do
	{
		if (waitpid(pid, &status, 0) == -1)
		{
			if (errno != EINTR)
				return -1;
		}
		else
			return status;
	}
	while (1);
}

static int execute_event(const char *action)
{
	int onerr;
	const char *onerrorstr;
	const scconf_list *actionlist;
	scconf_block **blocklist, *myblock;

	blocklist = scconf_find_blocks(ctx, root, "event", action);
	if (!blocklist)
	{
		DBG("Event block list not found");
		return -1;
	}
	myblock = blocklist[0];
	free(blocklist);
	if (!myblock)
	{
		DBG1("Event item not found: '%s'", action);
		return -1;
	}
	onerrorstr = scconf_get_str(myblock, "on_error", "ignore");
	if (!strcmp(onerrorstr, "ignore"))
		onerr = ONERROR_IGNORE;
	else if (!strcmp(onerrorstr, "return"))
		onerr = ONERROR_RETURN;
	else if (!strcmp(onerrorstr, "quit"))
		onerr = ONERROR_QUIT;
	else
	{
		onerr = ONERROR_IGNORE;
		DBG1("Invalid onerror value: '%s'. Assumed 'ignore'", onerrorstr);
	}
	/* search actions */
	actionlist = scconf_find_list(myblock, "action");
	if (!actionlist)
	{
		DBG1("No action list for event '%s'", action);
		return 0;
	}
	DBG1("Onerror is set to: '%s'", onerrorstr);
	while (actionlist)
	{
		int res;
		char *action_cmd = actionlist->data;
		DBG1("Executing action: '%s'", action_cmd);
		/*
		   there are some security issues on using system() in
		   setuid/setgid programs. so we will use an alternate function
		 */
		/* res=system(action_cmd); */
		res = my_system(action_cmd);
		actionlist = actionlist->next;
		/* evaluate return and take care on "onerror" value */
		DBG2("Action '%s' returns %d", action_cmd, res);
		if (!res)
			continue;
		switch (onerr)
		{
			case ONERROR_IGNORE:
				continue;
			case ONERROR_RETURN:
				return 0;
			case ONERROR_QUIT:
				thats_all_folks();
				exit(0);
			default:
				DBG("Invalid onerror value");
				return -1;
		}
	}
	return 0;
}

static int parse_config_file(void)
{
	ctx = scconf_new(cfgfile);
	if (!ctx)
	{
		DBG("Error creating conf context");
		return -1;
	}

	if (scconf_parse(ctx) <= 0)
	{
		DBG1("Error parsing file '%s'", cfgfile);
		return -1;
	}

	/* now parse options */
	root = scconf_find_block(ctx, NULL, "pkcs11_eventmgr");
	if (!root)
	{
		DBG1("pkcs11_eventmgr block not found in config: '%s'", cfgfile);
		return -1;
	}

	debug = scconf_get_bool(root, "debug", debug);
	daemonize = scconf_get_bool(root, "daemon", daemonize);
	polling_time = scconf_get_int(root, "polling_time", polling_time);
	expire_time = scconf_get_int(root, "expire_time", expire_time);
	pkcs11_module =
		(char *) scconf_get_str(root, "pkcs11_module", pkcs11_module);
#ifdef HAVE_NSS
	nss_dir = (char *) scconf_get_str(root, "nss_dir", nss_dir);
#endif
	if (debug)
		set_debug_level(1);
	return 0;
}

static int parse_args(int argc, char *argv[])
{
	int i;
	polling_time = DEF_POLLING;
	expire_time = DEF_EXPIRE;
	debug = 0;
	daemonize = 0;
	cfgfile = DEF_CONFIG_FILE;

	/* first of all check whether debugging should be enabled */
	for (i = 0; i < argc; i++)
	{
		if (!strcmp("debug", argv[i]))
			set_debug_level(1);
	}

	/* try to find a configuration file entry */
	for (i = 0; i < argc; i++)
	{
		if (strstr(argv[i], "config_file="))
		{
			cfgfile = 1 + strchr(argv[i], '=');
			break;
		}
	}

	/* parse configuration file */
	if (parse_config_file() < 0)
	{
		fprintf(stderr, "Error parsing configuration file %s\n", cfgfile);
		exit(-1);
	}

	/* and now re-parse command line to take precedence over cfgfile */
	for (i = 1; i < argc; i++)
	{
		if (strcmp("daemon", argv[i]) == 0)
		{
			daemonize = 1;
			continue;
		}
		if (strcmp("nodaemon", argv[i]) == 0)
		{
			daemonize = 0;
			continue;
		}
		if (strstr(argv[i], "polling_time="))
		{
			sscanf(argv[i], "polling_time=%d", &polling_time);
			continue;
		}
		if (strstr(argv[i], "expire_time="))
		{
			sscanf(argv[i], "expire_time=%d", &expire_time);
			continue;
		}
		if (strstr(argv[i], "pkcs11_module="))
		{
			pkcs11_module = 1 + strchr(argv[i], '=');
			continue;
		}
#ifdef HAVE_NSS
		if (strstr(argv[i], "nss_dir="))
		{
			nss_dir = 1 + strchr(argv[i], '=');
			continue;
		}
#endif
		if (strstr(argv[i], "debug"))
		{
			continue;			/* already parsed: skip */
		}
		if (strstr(argv[i], "nodebug"))
		{
			set_debug_level(0);
			continue;			/* already parsed: skip */
		}
		if (strstr(argv[i], "config_file="))
		{
			continue;			/* already parsed: skip */
		}
		fprintf(stderr, "unknown option %s\n", argv[i]);
		/* arriving here means syntax error */
		fprintf(stderr, "PKCS#11 Event Manager\n\n");
		fprintf(stderr,
			"Usage %s [[no]debug] [[no]daemon] [polling_time=<time>] [expire_time=<limit>] [config_file=<file>] [pkcs11_module=<module>]\n",
			argv[0]);
		fprintf(stderr,
			"\n\nDefaults: debug=0 daemon=0 polltime=%d (ms) expiretime=0 (none) config_file=%s pkcs11_module=%s\n",
			DEF_POLLING, DEF_CONFIG_FILE, DEF_PKCS11_MODULE);
		exit(1);
	}							/* for */
	/* end of config: return */
	return 0;
}

#ifdef HAVE_NSS
struct SlotStatusStr
{
	CK_SLOT_ID slotID;
	PRUint32 series;
	int present;
};

struct SlotStatusStr *slotStatus = NULL;
int slotCount = 0;
int maxEntries = 0;

static int do_expand_slot_status(void)
{
#define ENTRY_STEP 10
	struct SlotStatusStr *tmp;
	tmp = (struct SlotStatusStr *)
		realloc(slotStatus,
		(maxEntries + ENTRY_STEP) * sizeof(struct SlotStatusStr));
	if (!tmp)
	{
		return 0;
	}
	slotStatus = tmp;
	maxEntries += ENTRY_STEP;
	return 1;
}

static struct SlotStatusStr *get_token_status(CK_SLOT_ID slotID)
{
	/* linear search is ok for modules with few slots, if we have modules with
	 * thousands of slots or more, we would need to revisit this */
	int i;

	for (i = 0; i < slotCount; i++)
	{
		if (slotStatus[i].slotID == slotID)
		{
			return &slotStatus[i];
		}
	}
	if (slotCount >= maxEntries)
	{
		if (!do_expand_slot_status())
		{
			return NULL;
		}
	}

	i = slotCount++;
	slotStatus[i].slotID = slotID;
	slotStatus[i].present = 0;
	slotStatus[i].series = 0;
	return &slotStatus[i];
}
#else
/*
* try to find a valid token from slot list
* returns CARD_PRESENT, CARD_NOT_PRESENT or CARD_ERROR
*/
static int get_a_token(void)
{
	int rv;
	unsigned long num_tokens = 0;
	/* get Number of of slots with valid tokens */
	rv = ph->fl->C_GetSlotList(TRUE, NULL, &num_tokens);
	if (rv != CKR_OK)
	{
		DBG1("C_GetSlotList() failed: %x", rv);
		return CARD_ERROR;
	}
	DBG1("Found %ld token(s)", num_tokens);
	if (num_tokens > 0)
		return CARD_PRESENT;
	return CARD_NOT_PRESENT;
}
#endif

int main(int argc, char *argv[])
{
#ifdef HAVE_NSS
	SECStatus rv;

	/* parse args and configuration file */
	parse_args(argc, argv);

	DBG("Initializing NSS ...");
	if (nss_dir)
	{
		/* initialize with read only databases */
		rv = NSS_Init(nss_dir);
	}
	else
	{
		/* not database secified */
		rv = NSS_NoDB_Init(NULL);
	}

	if (rv != SECSuccess)
	{
		DBG("NSS_Initialize failed.");
		return 1;
	}

	/* acquire the module before we daemonize so we can return an error
	 * to the user if it fails */
	DBG("loading the module ...");
	if (pkcs11_module)
	{
#define SPEC_TEMPLATE "library=\"%s\" name=\"SmartCard\""
		char *moduleSpec =
			malloc(sizeof(SPEC_TEMPLATE) + strlen(pkcs11_module));
		if (!moduleSpec)
		{
			DBG1("Malloc failed when allocating module spec: %s",
				strerror(errno));
			return 1;
		}
		sprintf(moduleSpec, SPEC_TEMPLATE, pkcs11_module);
		DBG2("loading Module explicitly, moduleSpec=<%s> module=%s\n",
			moduleSpec, pkcs11_module);
		module = SECMOD_LoadUserModule(moduleSpec, NULL, 0);
		free(moduleSpec);
		if (!module || module->loaded == 0)
		{
			if (module)
			{
				SECMOD_DestroyModule(module);
			}
			DBG("Failed to load SmartCard software");
			return 1;
		}
	}
	else
	{
		/* no module specified? look for one in the our of NSS's
		 * secmod.db */
		SECMODModuleList *modList = SECMOD_GetDefaultModuleList();

		/* threaded applications should also acquire the
		 * DefaultModuleListLock */
		DBG("Looking up new module\n");
		for (; modList; modList = modList->next)
		{
			if (SECMOD_HasRemovableSlots(modList->module))
			{
				module = SECMOD_ReferenceModule(modList->module);
				break;
			}
		}
		if (!module)
		{
			DBG("Failed to find any SmartCard software");
			return 1;
		}
	}

#ifdef HAVE_DAEMON
	if (daemonize)
	{
		DBG("Going to be daemon...");
		if (daemon(0, debug) < 0)
		{
			DBG1("Error in daemon() call: %s", strerror(errno));
			SECMOD_DestroyModule(module);
			rv = NSS_Shutdown();
			if (ctx)
				scconf_free(ctx);
			return 1;
		}
	}
#endif

	/*
	 * Wait endlessly for all events in the list of readers
	 * We only stop in case of an error
	 *
	 */
	DBG("Waiting for Events");
	do
	{
		/* wait for any token uses C_WaitForSlotEvent if the token supports it.
		 * otherwise it polls by hand*/
		struct SlotStatusStr *slotStatus;
		PK11SlotInfo *slot = SECMOD_WaitForAnyTokenEvent(module, 0,
			PR_SecondsToInterval(polling_time));

		/* exit on an error */
		if (slot == NULL)
		{
			break;
		}

		/* examine why we got the event */
		slotStatus = get_token_status(PK11_GetSlotID(slot));

		/* if the slot is present, see if it was just removed */
		if (PK11_IsPresent(slot))
		{
			PRUint32 series = PK11_GetSlotSeries(slot);

			/* skip spurious insert events */
			if (series != slotStatus->series)
			{
#ifdef notdef
				/* if one was already present, remove it
				 * This can happen if you pull the token and insert it
				 * before the PK11_IsPresent call above */
				if (slotStatus->present)
				{
					DBG("Card removed, ");
					execute_event("card_remove");
				}
#endif
				DBG("Card inserted, ");
				execute_event("card_insert");
			}
			slotStatus->series = series;
			slotStatus->present = 1;
		}
		else
		{
			if (slotStatus->present)
			{
				DBG("Card removed, ");
				execute_event("card_remove");
			}
			slotStatus->series = 0;
			slotStatus->present = 0;
		}
		PK11_FreeSlot(slot);
	}
	while (1);

#else
	int rv;

	int first_loop = 0;
	int old_state = CARD_NOT_PRESENT;
	int new_state = CARD_NOT_PRESENT;
	int expire_count = 0;

	/* parse args and configuration file */
	parse_args(argc, argv);
	/* load pkcs11 module */
	DBG("loading pkcs #11 module...");
	rv = load_pkcs11_module(pkcs11_module, &ph);
	if (rv != 0)
	{
		DBG1("load_pkcs11_module() failed: %s", get_error());
		return 1;
	}

#ifdef HAVE_DAEMON
	/* put my self into background if flag is set */
	if (daemonize)
	{
		DBG("Going to be daemon...");
		if (daemon(0, debug) < 0)
		{
			DBG1("Error in daemon() call: %s", strerror(errno));
			release_pkcs11_module(ph);
			if (ctx)
				scconf_free(ctx);
			return 1;
		}
	}
#endif

	/* open pkcs11 sesion */
	DBG("initialising pkcs #11 module...");
	rv = ph->fl->C_Initialize(NULL);
	if (rv != 0)
	{
		release_pkcs11_module(ph);
		if (ctx)
			scconf_free(ctx);
		DBG1("C_Initialize() failed: %d", rv);
		return 1;
	}
	ph->should_finalize = 1;

	/*
	 * Wait endlessly for all events in the list of readers
	 * We only stop in case of an error
	 *
	 * COMMENT:
	 * There are no way in pkcs11 API to detect if a card is present or no
	 * so the way we proced is to look for an slot whit available token
	 * Any ideas will be wellcomed
	 *
	 * REVIEW:
	 * Errrh, well, above note is not exactly true: pkcs11v2.1 API defines
	 * C_WaitForSlotEvent(). But it's known that is not supported in all
	 * pkcs11 implementations, and seems to be buggy in multithreaded
	 * environments....
	 */
	do
	{
		sleep(polling_time);
		/* try to find an slot with available token(s) */
		new_state = get_a_token();
		if (new_state == CARD_ERROR)
		{
			DBG("Error trying to get a token");
			rv = ph->fl->C_Finalize(NULL);
			if (rv != CKR_OK)
			{
				DBG1("C_Finalize() failed: %x", rv);
				return CARD_ERROR;
			}
			rv = ph->fl->C_Initialize(NULL);
			if (rv != CKR_OK)
			{
				DBG1("C_Initialize() failed: %x", rv);
				return CARD_ERROR;
			}
			break;
		}
		if (old_state == new_state)
		{						/* state unchanged */
			/* on card not present, increase and check expire time */
			if (expire_time == 0)
				continue;
			if (new_state == CARD_PRESENT)
				continue;
			expire_count += polling_time;
			if (expire_count >= expire_time)
			{
				DBG("Timeout on Card Removed ");
				execute_event("expire_time");
				expire_count = 0;	/*restart timer */
			}
		}
		else
		{						/* state changed; parse event */
			old_state = new_state;
			expire_count = 0;
			if (!first_loop++)
				continue;		/*skip first pass */
			if (new_state == CARD_NOT_PRESENT)
			{
				DBG("Card removed, ");
				execute_event("card_remove");
				/*
				   some pkcs11's fails on reinsert card. To avoid this
				   re-initialize library on card removal
				 */
				DBG("Re-initialising pkcs #11 module...");
				rv = ph->fl->C_Finalize(NULL);
				if (rv != CKR_OK)
				{
					DBG1("C_Finalize() failed: %x", rv);
					return CARD_ERROR;
				}
				rv = ph->fl->C_Initialize(NULL);
				if (rv != CKR_OK)
				{
					DBG1("C_Initialize() failed: %x", rv);
					return CARD_ERROR;
				}
			}
			if (new_state == CARD_PRESENT)
			{
				DBG("Card inserted, ");
				execute_event("card_insert");
			}
		}
	}
	while (1);
#endif
	/* If we get here means that an error or exit status occurred */
	DBG("Exited from main loop");
	thats_all_folks();
	exit(0);
}								/* main */
