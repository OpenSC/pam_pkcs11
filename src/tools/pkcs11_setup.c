/*
 * PKCS#11 Card viewer tool
 * Copyright (C) 2006 Red Hat, Inc.
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
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"

#define PAM_PKCS11_CONF "/etc/pam_pkcs11/pam_pkcs11.conf"
#define EVENTMGR_CONF "/etc/pam_pkcs11/pkcs11_eventmgr.conf"

static const char Ins_action[] = "ins_action=";
static const char Rm_action[] = "rm_action=";
static const char Use_module[] = "use_module=";
static const char List_modules[] = "list_modules";

enum params { INS_ACTION, RM_ACTION, USE_MODULE, LIST_MODULES };

static const char *param_names[] = { Ins_action, Rm_action, Use_module, List_modules };
static int pn_sizes[] = { sizeof(Ins_action), sizeof(Rm_action), sizeof(Use_module), sizeof(List_modules) };

#define NUM_PARAMS (sizeof(param_names)/sizeof(param_names[0]))

static const char *scconf_replace_str(scconf_block * block, const char *option, const char *value)
{
    scconf_list *list = NULL;
    scconf_item *item;

    scconf_list_add(&list, value);
    item = scconf_item_add(NULL, block, NULL, SCCONF_ITEM_TYPE_VALUE, option, list);

    /* now clear out the item list */
    scconf_list_destroy(item->value.list);
    item->value.list = list;  /* adopt */
    return value;
}

static int scconf_replace_str_list(scconf_block * block, const char *option, const char *value)
{
    scconf_list *list = NULL;
    scconf_item *item;
    char *lstitem = NULL;
    char *next;
    
    while (value != NULL) {
        if ((next=strchr(value, ',')) != NULL) {
            lstitem = strndup(value, next-value);
            next++;
        }
        else {
            lstitem = strdup(value);
        }
        if (lstitem == NULL)
            return 1;
        scconf_list_add(&list, lstitem);
        value = next;
        free(lstitem);
    }
        
    item = scconf_item_add(NULL, block, NULL, SCCONF_ITEM_TYPE_VALUE, option, list);

    /* now clear out the item list */
    scconf_list_destroy(item->value.list);
    item->value.list = list;  /* adopt */
    return 0;
}

static int list_modules(void)
{
    const scconf_block *pam_pkcs11;
    scconf_block **pkcs11_blocks;
    scconf_context *ctx = NULL;
    int i;
    int result = 1;

    /*
     * loop through looking for smart card entries
     */
    ctx = scconf_new(PAM_PKCS11_CONF);
    if (ctx == NULL) {
    	goto bail;
    }
    if (scconf_parse(ctx) <= 0 ) {
    	goto bail;
    }
    pam_pkcs11 = scconf_find_block(ctx, NULL, "pam_pkcs11");
    if (!pam_pkcs11) {
    	goto bail;
    }
    pkcs11_blocks = scconf_find_blocks(ctx, pam_pkcs11, "pkcs11_module", NULL);
    if (!pkcs11_blocks) {
    	goto bail;
    }

    /* list only those smart cards which are actually installed */
    for (i=0; pkcs11_blocks[i]; i++) {
    	void *libhandle;
    	const char *path = 
    		scconf_get_str(pkcs11_blocks[i], "module", NULL);
    	/* check to see if the module exists on the system */
    	if (!path || *path == 0) {
    		continue;
    	}
    	/* verify the module exists */
        if ((libhandle=dlopen(path, RTLD_LAZY)) != NULL) {
    	    dlclose(libhandle);
    	    if (pkcs11_blocks[i] && pkcs11_blocks[i]->name
    	        && pkcs11_blocks[i]->name->data) {
    		    printf("%s\n", pkcs11_blocks[i]->name->data);
    	    }
    	}
    }
    
    result = 0;

bail: 
    if (ctx) {
    	scconf_free(ctx);
    }
    return result;
}

static int print_default_module(void)
{
    const scconf_block *pam_pkcs11;
    scconf_context *ctx = NULL;
    int result = 1;

    /*
    * read the base pam_pkcs11.conf
    */
    ctx = scconf_new(PAM_PKCS11_CONF);
    if (ctx == NULL) {
        goto bail;
    }
    if (scconf_parse(ctx) <= 0) {
        goto bail;
    }
    pam_pkcs11 = scconf_find_block(ctx, NULL, "pam_pkcs11");
    if (!pam_pkcs11) {
        goto bail;
    }
    printf("%s\n", scconf_get_str(pam_pkcs11, "use_pkcs11_module", ""));
    result = 0;

    bail: 
    if (ctx) {
        scconf_free(ctx);
    }
    ctx = NULL;

    return result;
}

static int set_default_module(const char *mod)
{
	scconf_block *pam_pkcs11, *pkcs11_eventmgr;
	scconf_block **modules = NULL;
	scconf_context *ctx = NULL;
	scconf_context *ectx = NULL;
	const char *lib = NULL;
	int result = 1;

	/*
	 * write out pam_pkcs11.conf
	 */
	ctx = scconf_new(PAM_PKCS11_CONF);
	if (ctx == NULL) {
		goto bail;
	}
	if (scconf_parse(ctx) <= 0) {
		goto bail;
	}
	pam_pkcs11 = (scconf_block *)scconf_find_block(ctx, NULL, "pam_pkcs11");
	if (!pam_pkcs11) {
		goto bail;
	}
	scconf_replace_str(pam_pkcs11, "use_pkcs11_module", mod);

	modules = scconf_find_blocks(ctx, pam_pkcs11, "pkcs11_module", mod);
	if (!modules || !modules[0]) {
		goto bail;
	}
	lib = scconf_get_str(modules[0], "module", NULL);
	if (!lib) {
		goto bail;
	}
	result = scconf_write(ctx, NULL);
	if (result != 0) {
	    goto bail;
	}

	ectx = scconf_new(EVENTMGR_CONF);
	if (ectx == NULL) {
		goto bail;
	}
	if (scconf_parse(ectx) <= 0) {
		goto bail;
	}
	pkcs11_eventmgr = (scconf_block *)
			scconf_find_block(ectx, NULL, "pkcs11_eventmgr");
	if (!pkcs11_eventmgr) {
		goto bail;
	}
	scconf_replace_str(pkcs11_eventmgr, "pkcs11_module", lib);
	result = scconf_write(ectx, NULL);

bail: 
	if (modules) {
		free(modules);
	}
	if (ctx) {
		scconf_free(ctx);
	}
	if (ectx) {
		scconf_free(ectx);
	}
	
	return result;
}

static int print_card_insert_action(void)
{
	const scconf_block *pkcs11_eventmgr;
	scconf_block **event_blocks = NULL;
	scconf_context *ctx = NULL;
	const scconf_list *actionList = NULL;
    int result = 1;

	/*
	 * read the pkcs11_eventmgr.conf to get our action
	 */
	ctx = scconf_new(EVENTMGR_CONF);
	if (ctx == NULL) {
		goto bail;
	}
	if (scconf_parse(ctx) <= 0) {
		goto bail;
	}
	pkcs11_eventmgr = scconf_find_block(ctx, NULL, "pkcs11_eventmgr");
	if (!pkcs11_eventmgr) {
		goto bail;
	}
	event_blocks = scconf_find_blocks(ctx, pkcs11_eventmgr, "event", 
						"card_insert");
	if (!event_blocks || !event_blocks[0]) {
		goto bail;
	}
	actionList = scconf_find_list(event_blocks[0],"action");
	if (actionList) {
	   char *lst = scconf_list_strdup(actionList, "\n");
	   if (lst != NULL) {
	       printf("%s\n", lst);
	       free(lst);
	   }
	}
	result = 0;

bail:
	if (event_blocks) {
		free(event_blocks);
	}
	if (ctx) {
		scconf_free(ctx);
	}

	return result;
}

static int set_card_insert_action(const char *act)
{
	scconf_block *pkcs11_eventmgr;
	scconf_block **insert_blocks = NULL;
	scconf_context *ctx = NULL;
    int result = 1;

	/*
	 * write out pkcs11_eventmgr.conf
	 */
	ctx = scconf_new(EVENTMGR_CONF);
	if (ctx == NULL) {
		goto bail;
	}
	if (scconf_parse(ctx) <= 0) {
		goto bail;
	}
	pkcs11_eventmgr = (scconf_block *)
			scconf_find_block(ctx, NULL, "pkcs11_eventmgr");
	if (!pkcs11_eventmgr) {
		goto bail;
	}
	insert_blocks = scconf_find_blocks(ctx, pkcs11_eventmgr, 
						"event", "card_insert");
	if (!insert_blocks || !insert_blocks[0]) {
		goto bail;
	}

	scconf_replace_str_list(insert_blocks[0], "action", act);

	result = scconf_write(ctx, NULL);

bail:
	if (insert_blocks) {
		free(insert_blocks);
	}
	if (ctx) {
		scconf_free(ctx);
	}
	return result;
}

static int print_card_remove_action(void)
{
	const scconf_block *pkcs11_eventmgr;
	scconf_block **event_blocks = NULL;
	scconf_context *ctx = NULL;
	const scconf_list *actionList = NULL;
    int result = 1;

	/*
	 * read the pkcs11_eventmgr.conf to get our action
	 */
	ctx = scconf_new(EVENTMGR_CONF);
	if (ctx == NULL) {
		goto bail;
	}
	if (scconf_parse(ctx) <= 0) {
		goto bail;
	}
	pkcs11_eventmgr = scconf_find_block(ctx, NULL, "pkcs11_eventmgr");
	if (!pkcs11_eventmgr) {
		goto bail;
	}
	event_blocks = scconf_find_blocks(ctx, pkcs11_eventmgr, "event", 
						"card_remove");
	if (!event_blocks || !event_blocks[0]) {
		goto bail;
	}
	actionList = scconf_find_list(event_blocks[0],"action");
	if (actionList) {
	   char *lst = scconf_list_strdup(actionList, "\n");
	   if (lst != NULL) {
	       printf("%s\n", lst);
	       free(lst);
	   }
	}
	result = 0;

bail:
	if (event_blocks) {
		free(event_blocks);
	}
	if (ctx) {
		scconf_free(ctx);
	}

	return result;
}

static int set_card_remove_action(const char *act)
{
	scconf_block *pkcs11_eventmgr;
	scconf_block **insert_blocks = NULL;
	scconf_context *ctx = NULL;
    int result = 1;

	/*
	 * write out pkcs11_eventmgr.conf
	 */
	ctx = scconf_new(EVENTMGR_CONF);
	if (ctx == NULL) {
		goto bail;
	}
	if (scconf_parse(ctx) <= 0) {
		goto bail;
	}
	pkcs11_eventmgr = (scconf_block *)
			scconf_find_block(ctx, NULL, "pkcs11_eventmgr");
	if (!pkcs11_eventmgr) {
		goto bail;
	}
	insert_blocks = scconf_find_blocks(ctx, pkcs11_eventmgr, 
						"event", "card_remove");
	if (!insert_blocks || !insert_blocks[0]) {
		goto bail;
	}

	scconf_replace_str_list(insert_blocks[0], "action", act);

	result = scconf_write(ctx, NULL);

bail:
	if (insert_blocks) {
		free(insert_blocks);
	}
	if (ctx) {
		scconf_free(ctx);
	}
	return result;
}

int main(int argc, const char **argv)
{
    int i;
    int pname;
    const char *params[NUM_PARAMS];
    
    memset(params, '\0', sizeof(params));
    
    for (i = 1; i < argc; i++) {
    	for (pname = 0; pname < NUM_PARAMS; pname++) {
    	    if (param_names[pname][pn_sizes[pname]-2] == '=') {
    	        if (strncmp(argv[i], param_names[pname], pn_sizes[pname]-1) == 0) {
    	            params[pname] = argv[i] + pn_sizes[pname] - 1;
    	        }
    	        else if (strncmp(argv[i], param_names[pname], pn_sizes[pname]-2) == 0
    	            && argv[i][pn_sizes[pname]-2] == '\0') {
    	            params[pname] = (void *)1;
    	        }
    	    }
    	    else {
        	    if (strcmp(argv[i], param_names[pname]) == 0) {
        	        params[pname] = (void *)1;
        	    }
        	} 
        }
    }
    
    for (pname = 0; pname < NUM_PARAMS; pname++) {
	    if (params[pname] != NULL)
	        break;
    }
    
    if (pname == NUM_PARAMS) {
	DBG("No correct parameter specified");
	printf("usage: pkcs11_setup [list_modules] [use_module[=<module_name>]]\n"
	       "                    [ins_action[=<executable,executable,...>]]\n"
	       "                    [rm_action[=<executable,executable,...>]]\n");
    }
    
    if (params[LIST_MODULES] != NULL) {
        DBG("List modules:");
        return list_modules();
    } 
    else {
        if (params[USE_MODULE] == (void *)1) {
            DBG("Print default module:");
            if ((i=print_default_module()) != 0) {
                DBG1("Print default module failed with: %d", i);
                return i;
            }
            return 0;
        }
        else if (params[USE_MODULE] != NULL) {
            DBG1("Set default module: %s", params[USE_MODULE]);
            if ((i=set_default_module(params[USE_MODULE])) != 0) {
                DBG1("Set default module failed with: %d", i);
                return i;
            }
        }
        if (params[INS_ACTION] == (void *)1) {
            DBG("Print card insert action:");
            if ((i=print_card_insert_action()) != 0) {
                DBG1("Print card insert action failed with: %d", i);
                return i;
            }
            return 0;
        }       
        else if (params[INS_ACTION] != NULL) {
            DBG1("Set card insert action: %s", params[INS_ACTION]);
            if ((i=set_card_insert_action(params[INS_ACTION])) != 0) {
                DBG1("Set card insert action failed with: %d", i);
                return i;
            }
        }
        if (params[RM_ACTION] == (void *)1) {
            DBG("Print card remove action:");
            if ((i=print_card_remove_action()) != 0) {
                DBG1("Set card remove action failed with: %d", i);
                return i;
            }
            return 0;
        }        
        else if (params[RM_ACTION] != NULL) {
            DBG1("Set card remove action: %s", params[RM_ACTION]);
            if ((i=set_card_remove_action(params[RM_ACTION])) != 0) {
                DBG1("Set card remove action failed with: %d", i);
                return i;
            }
        }        
    }
    DBG("Process completed");
    return 0;
}
