/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
 * Mapper module copyright (c) 2005 Juan Antonio Martinez <jonsito@teleline.es>
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

/*
* this module manages dynamic load of mapping modules
* also is used as entry point for cert matching routines
*/

#define _MAPPER_MGR_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <dlfcn.h>
#include "../common/cert_st.h"

#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../mappers/mapper.h"
#include "../mappers/mapperlist.h"
#include "mapper_mgr.h"

struct mapper_listitem *root_mapper_list;

/*
* load and initialize a module
* returns descriptor on success, null on fail
*/
struct mapper_instance *load_module(scconf_context *ctx, const char * name) {

	const scconf_block *root;
	scconf_block **blocks, *blk;
	struct mapper_instance *mymodule;
	mapper_module * (*mapper_init)(scconf_block *blk, const char *mapper_name);
	void *handler = NULL;
	int old_level=get_debug_level();
	const char *libname = NULL;
	mapper_module * res = NULL;

	/* get module info */
	root = scconf_find_block(ctx,NULL,"pam_pkcs11");
	if(!root) return NULL; /* no pam_pkcs11 { ...  } root block */
	blocks = scconf_find_blocks(ctx,root,"mapper",name);
	if (!blocks) return NULL; /* named mapper not found */
	blk=blocks[0]; /* should only be one */
	free(blocks);
	if (!blk) {
	    DBG1("Mapper entry '%s' not found. Assume static module with default values",name);
	} else {
	    /* compose module path */
 	    libname = scconf_get_str(blk, "module", NULL);
	}
	if ( (!blk) || (!libname) || (!strcmp(libname,"internal")) ) {
	    int n;
	    DBG1("Loading static module for mapper '%s'",name);
	    libname = NULL;
	    handler = NULL;
	    mapper_init = NULL;
	    for(n=0;static_mapper_list[n].name;n++) {
		if (strcmp(static_mapper_list[n].name,name)) continue;
		/* match found: get data */
		mapper_init = static_mapper_list[n].init;
	        res= mapper_init(blk,name);
	        if (!res ) { /* init failed */
		    DBG1("Static mapper %s init failed",name);
		    return NULL;
	        }
		/* save dbg level of mapper and restore previous one */
		res->dbg_level=get_debug_level();
		set_debug_level(old_level);
	    }
	    if ( !mapper_init ) {
		DBG1("Static mapper '%s' not found",name);
		return NULL;
	    }
	} else if (blk) { /* assume dynamic module */
	    DBG1("Loading dynamic module for mapper '%s'",name);
	    handler= dlopen(libname,RTLD_NOW);
	    if (!handler) {
		DBG3("dlopen failed for module:  %s path: %s Error: %s",name,libname,dlerror());
		return NULL;
	    }
	    mapper_init = ( mapper_module * (*)(scconf_block *blk, const char *mapper_name) )
		dlsym(handler,"mapper_module_init");
	    if ( !mapper_init) {
		dlclose(handler);
		DBG1("Module %s is not a mapper",name);
		return NULL;
	    }
	    res= mapper_init(blk,name);
	    if (!res ) { /* init failed */
		DBG1("Module %s init failed",name);
		dlclose(handler);
		return NULL;
	    }
	    /* save dbg level of mapper and restore previous one */
	    res->dbg_level=get_debug_level();
	    set_debug_level(old_level);
	}
	/* allocate data */
	mymodule = malloc (sizeof(struct mapper_instance));
	if (!mymodule) {
		DBG1("No space to alloc module entry: '%s'",name);
		return NULL;
	}
	mymodule->module_handler=handler;
	mymodule->module_name=name;
	mymodule->module_path=libname;
	mymodule->module_data=res;
	/* that's all folks */
	return mymodule;
}

void unload_module( struct mapper_instance *module ) {
	if (!module) {
		DBG("Trying to unmap empty module");
		return;
	}
	DBG1("calling mapper_module_end() %s",module->module_name);
	if ( module->module_data->deinit ) {
		int old_level= get_debug_level();
		set_debug_level(module->module_data->dbg_level);
		(*module->module_data->deinit)(module->module_data->context);
		set_debug_level(old_level);
	}
	if (module->module_handler) {
		DBG1("unloading module %s",module->module_name);
		dlclose(module->module_handler);
	} else {/* static mapper module */
		DBG1("Module %s is static: don't remove",module->module_name);
	}
	if(module->module_data) {
		free(module->module_data);
	}
	module->module_data=NULL;
	/* don't free name and libname: they are elements of
	scconf tree */
	free(module);
	return;
}

/**
* compose mapper module chain
*/

struct mapper_listitem *load_mappers( scconf_context *ctx ) {
	struct mapper_listitem *last =NULL;
	const scconf_list *module_list = NULL;
	const scconf_block *root= NULL;
	root_mapper_list = NULL;
	/* extract mapper list */
	root = scconf_find_block(ctx,NULL,"pam_pkcs11");
	if (!root) {
		DBG("No pam_pkcs11 block in config file");
		return NULL;
	}
	DBG("Retrieveing mapper module list");
	root = scconf_find_block(ctx, NULL, "pam_pkcs11");
        if (!root) {
	   /* should not occurs, but Murphy says.. */
           DBG("pam_pkcs11 block not found in config file");
           return NULL;
        }
	module_list = scconf_find_list(root,"use_mappers");
	if (!module_list) {
           DBG("No use_mappers entry found in config");
           return NULL;
	}
	while (module_list) {
	    char *name = module_list->data;
	    struct mapper_instance *module = load_module(ctx,name);
	    if (module) {
	    	struct mapper_listitem *item = malloc(sizeof(struct mapper_listitem));
		if (!item) {
			DBG1("Error allocating modulelist entry: %s",name);
			unload_module(module);
			return NULL;
		}
		item->module = module;
		item->next = NULL;
		DBG1("Inserting mapper [%s] into list",name);
	    	if (!last) { /* empty list */
			last = item;
			root_mapper_list = item;
	    	} else { /* insert at end of list */
			last->next= item;
			last = item;
		}
	    }
	    module_list = module_list->next;
	}
	return root_mapper_list;
}

void unload_mappers(void) {
	struct mapper_listitem *next;
	struct mapper_listitem *item = root_mapper_list;
	DBG("unloading mapper module list");
	while (item) {
		next=item->next;
		/* free the module */
		unload_module(item->module);
		/* free the list item */
		free(item);
		item=next;
	}
	root_mapper_list=NULL;
	return;
}

void inspect_certificate(X509 *x509) {
	int old_level=get_debug_level();
	struct mapper_listitem *item = root_mapper_list;
	if (!x509) return;
	while (item) {
	    char *str=NULL;
	    char **data=NULL;
	    if (! item->module->module_data->entries) {
	    	DBG1("Mapper '%s' has no inspect() function",item->module->module_name);
	        item=item->next;
		continue;
	    }
	    set_debug_level(item->module->module_data->dbg_level);
	    data = (*item->module->module_data->entries)(x509,item->module->module_data->context);
	    set_debug_level(old_level);
	    if (!data) {
	    	DBG1("Cannot find cert data for mapper %s",item->module->module_name);
	        item=item->next;
		continue;
	    }
	    printf("Printing data for mapper %s:\n",item->module->module_name);
	    for (str=*data; str; str=*++data)
		    fprintf(stdout,"%s\n",str);
	    item=item->next;
	}
}

/*
* this function search mapper module list until
* find a module that returns a login name for
* provided certificate
*/
char * find_user(X509 *x509) {
	int old_level= get_debug_level();
	struct mapper_listitem *item = root_mapper_list;
	if (!x509) return NULL;
	while (item) {
	    char *login = NULL;
	    if(! item->module->module_data->finder) {
	    	DBG1("Mapper '%s' has no find() function",item->module->module_name);
	    } else {
			int match = 0;

			set_debug_level(item->module->module_data->dbg_level);
	        login = (*item->module->module_data->finder)(x509,item->module->module_data->context, &match);
		set_debug_level(old_level);
	    	DBG3("Mapper '%s' found %s, matched %d", item->module->module_name,login, match);
			if (login) {
				if (match)
					return login;
				free(login);
			}
	    }
	    item=item->next;
	}
	return NULL;
}

/**
* This function search mapper module list until
* find a module that match provided login name
* if login is null, call find_user and returns 1,or 0 depending on user found
* @return 1 if match
*         0 on no match
*         -1 on error
*/
int match_user(X509 *x509, const char *login) {
	int old_level= get_debug_level();
	struct mapper_listitem *item = root_mapper_list;
	if (!x509) return -1;
	/* if no login provided, call  */
	if (!login) return 0;
	while (item) {
	    int res=0; /* default: no match */
	    if (!item->module->module_data->matcher) {
	    	DBG1("Mapper '%s' has no match() function",item->module->module_name);
	    } else {
		set_debug_level(item->module->module_data->dbg_level);
	        res = (*item->module->module_data->matcher)(x509,login,item->module->module_data->context);
		set_debug_level(old_level);
	        DBG2("Mapper module %s match() returns %d",item->module->module_name,res);
	    }
	    if (res>0) return res;
	    if (res<0) { /* show error and continue */
	    	DBG1("Error in module %s",item->module->module_name);
	    }
	    item=item->next;
	}
	return 0;
}

