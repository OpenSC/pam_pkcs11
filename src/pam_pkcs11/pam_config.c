/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
 * config mgmt copyright (c) 2005 Juan Antonio Martinez <jonsito@teleline.es>
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

#define _PAM_CONFIG_C_

#include <syslog.h>
#include <string.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/cert_vfy.h"
#include "pam_config.h"
#include "mapper_mgr.h"

/*
* configuration related functions
*/

struct configuration_st configuration = {
	"/etc/pam_pkcs11/pam_pkcs11.conf",	/* char * config_file; */
	NULL,				/* scconf_context *ctx; */
        0,				/* int debug; */
        0,				/* int nullok; */
        0,				/* int try_first_pass; */
        0,				/* int use_first_pass; */
        0,				/* int use_authok; */
        "default", 			/* const char *pkcs11_module; */
        "/etc/pam_pkcs11/pkcs11_module.so",/* const char *pkcs11_module_path; */
        0,				/* int slot_num; */
	/* cert policy; */
        { 0,CRLP_NONE,0,"/etc/pam_pkcs11/cacerts","/etc/pam_pkcs11/crls" },
	NULL				/* char *username */
};

void display_config () {
        DBG1("debug %d",configuration.debug);
        DBG1("nullok %d",configuration.nullok);
        DBG1("try_first_pass %d",configuration.try_first_pass);
        DBG1("use_first_pass %d", configuration.use_first_pass);
        DBG1("use_authok %d", configuration.use_authok);
        DBG1("pkcs11_module %s",configuration.pkcs11_module);
        DBG1("slot_num %d",configuration.slot_num);
        DBG1("ca_dir %s",configuration.policy.ca_dir);
        DBG1("crl_dir %s",configuration.policy.crl_dir);
        DBG1("ca_policy %d",configuration.policy.ca_policy);
        DBG1("crl_policy %d",configuration.policy.crl_policy);
        DBG1("signature_policy %d",configuration.policy.signature_policy);
}

/*
parse configuration file
*/
void parse_config_file() {
	scconf_block **pkcs11_mblocks,*pkcs11_mblk;
	const scconf_list *mapper_list;
	const scconf_list *policy_list;
	scconf_context *ctx;
	const scconf_block *root;
	configuration.ctx = scconf_new(configuration.config_file);
	if (!configuration.ctx) {
           DBG("Error creating conf context");
	   return;
	}
	ctx = configuration.ctx;
	if ( scconf_parse(ctx) <=0 ) {
           DBG1("Error parsing file %s",configuration.config_file);
	   return;
	}
	/* now parse options */
	root = scconf_find_block(ctx, NULL, "pam_pkcs11");
	if (!root) {
           DBG1("pam_pkcs11 block not found in config: %s",configuration.config_file);
	   return;
	}
	configuration.nullok = 
	    scconf_get_bool(root,"nullok",configuration.nullok);
	configuration.debug = 
	    scconf_get_bool(root,"debug",configuration.debug);
	if (configuration.debug) set_debug_level(1);
	else set_debug_level(0);
	configuration.use_first_pass = 
	    scconf_get_bool(root,"use_first_pass",configuration.use_first_pass);
	configuration.try_first_pass = 
	    scconf_get_bool(root,"try_first_pass",configuration.try_first_pass);
	configuration.use_authok = 
	    scconf_get_bool(root,"use_authok",configuration.use_authok);
	configuration.pkcs11_module = ( char * )
	    scconf_get_str(root,"use_pkcs11_module",configuration.pkcs11_module);
	/* search pkcs11 module options */
	pkcs11_mblocks = scconf_find_blocks(ctx,root,"pkcs11_module",configuration.pkcs11_module);
        if (!pkcs11_mblocks) {
           DBG1("Pkcs11 module name not found: %s",configuration.pkcs11_module);
	} else {
            pkcs11_mblk=pkcs11_mblocks[0]; /* should only be one */
            free(pkcs11_mblocks);
	    if (!pkcs11_mblk) {
               DBG1("No module entry: %s",configuration.pkcs11_module);
	    }
	    configuration.pkcs11_modulepath = (char *)
	        scconf_get_str(pkcs11_mblk,"module",configuration.pkcs11_modulepath);
	    configuration.policy.ca_dir = (char *)
	        scconf_get_str(pkcs11_mblk,"ca_dir",configuration.policy.ca_dir);
	    configuration.policy.crl_dir = (char *)
	        scconf_get_str(pkcs11_mblk,"crl_dir",configuration.policy.crl_dir);
	    configuration.slot_num = 
	        scconf_get_int(pkcs11_mblk,"slot_num",configuration.slot_num);
	    policy_list= scconf_find_list(pkcs11_mblk,"cert_policy");
	    while(policy_list) {
	        if ( !strcmp(policy_list->data,"none") ) {
			configuration.policy.crl_policy=CRLP_NONE;
			configuration.policy.ca_policy=0;
			configuration.policy.signature_policy=0;
			break;
		} else if ( !strcmp(policy_list->data,"crl_auto") ) {
			configuration.policy.crl_policy=CRLP_AUTO;
		} else if ( !strcmp(policy_list->data,"crl_online") ) {
			configuration.policy.crl_policy=CRLP_ONLINE;
		} else if ( !strcmp(policy_list->data,"crl_offline") ) {
			configuration.policy.crl_policy=CRLP_OFFLINE;
		} else if ( !strcmp(policy_list->data,"ca") ) {
			configuration.policy.ca_policy=1;
		} else if ( !strcmp(policy_list->data,"signature") ) {
			configuration.policy.signature_policy=1;
		} else {
                   DBG1("Invalid CRL policy: %s",policy_list->data);
	        }
		policy_list= policy_list->next;
	    }
	}
	/* now obtain and initialize mapper list */
	mapper_list = scconf_find_list(root,"use_mappers");
	if (!mapper_list) {
           DBG1("No mappers specified in config: %s",configuration.config_file);
	   return;
	}
	/* load_mappers(ctx); */
	/* that's all folks: return */
	return;
}

/*
* values are taken in this order (low to high precedence):
* 1- default values
* 2- configuration file
* 3- commandline arguments options
*/
struct configuration_st *pk_configure( int argc, const char **argv ) {
	int i;
	int res;
	/* try to find a configuration file entry */
	for (i = 0; i < argc; i++) {
	    if (strstr(argv[i],"config_file=") ) {
		configuration.config_file=1+strchr(argv[i],'=');
		break;
	    }
    	}
	DBG1("Using config file %s",configuration.config_file);
	/* parse configuration file */
	parse_config_file();
	/* display_config(); */
	/* finally parse provided arguments */
	/* skip argv[0] :-) */
	for (i = 1; i < argc; i++) {
	   if (strcmp("nullok", argv[i]) == 0) {
		configuration.nullok = 1;
		continue;
	   }
    	   if (strcmp("try_first_pass", argv[i]) == 0) {
      		configuration.try_first_pass = 1;
		continue;
	   }
    	   if (strcmp("use_first_pass", argv[i]) == 0) {
      		configuration.use_first_pass = 1;
		continue;
	   }
    	   if (strcmp("debug", argv[i]) == 0) {
      		configuration.debug = 1;
		set_debug_level(1);
		continue;
	   }
    	   if (strcmp("nodebug", argv[i]) == 0) {
      		configuration.debug = 0;
		set_debug_level(0);
		continue;
	   }
	   if (strstr(argv[i],"pcs11_module=") ) {
		res=sscanf(argv[i],"pkcs11_module=%255s",configuration.pkcs11_module);
		continue;
	   }
	   if (strstr(argv[i],"slot_num=") ) {
		res=sscanf(argv[i],"slot_nume=%d",&configuration.slot_num);
		continue;
	   }
	   if (strstr(argv[i],"ca_dir=") ) {
		res=sscanf(argv[i],"ca_dir=%255s",configuration.policy.ca_dir);
		continue;
	   }
	   if (strstr(argv[i],"crl_dir=") ) {
		res=sscanf(argv[i],"crl_dir=%255s",configuration.policy.crl_dir);
		continue;
	   }
	   if (strstr(argv[i],"cert_policy=") ) {
		if (strstr(argv[i],"none")) {
			configuration.policy.crl_policy=CRLP_NONE;
			configuration.policy.ca_policy=0;
			configuration.policy.signature_policy=0;
		}
		if (strstr(argv[i],"crl_online")) {
			configuration.policy.crl_policy=CRLP_ONLINE;
		}
		if (strstr(argv[i],"crl_offline")) {
			configuration.policy.crl_policy=CRLP_OFFLINE;
		}
		if (strstr(argv[i],"crl_auto")) {
			configuration.policy.crl_policy=CRLP_AUTO;
		}
		if (strstr(argv[i],"ca")) {
			configuration.policy.ca_policy=1;
		}
		if (strstr(argv[i],"signature")) {
			configuration.policy.signature_policy=1;
		}
		continue;
	   }
	   if (strstr(argv[i],"config_file=") ) {
		/* already parsed, skip */
		continue;
	   }
    	   /* if argument is not recognised, log error message */
           syslog(LOG_ERR, "argument %s is not supported by this module", argv[i]);
           DBG1("argument %s is not supported by this module", argv[i]);
	}
	return &configuration;
}

