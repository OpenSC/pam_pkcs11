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

#ifndef _MAPPER_MGR_H_
#define _MAPPER_MGR_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/x509.h>

#include "../scconf/scconf.h"
#include "../mappers/mapper.h"

/*
* mapper module descriptor
*/
struct mapper_instance {
    void *module_handler;
    const char *module_name;
    const char *module_path;
    mapper_module *module_data;
};

/*
* mapper module list
*/
struct mapper_listitem {
	struct mapper_instance *module;
	struct mapper_listitem *next;
};

/*
* load and initialize a module
* returns descriptor on success, null on fail
*/
struct mapper_instance *load_module(scconf_context *ctx, const char * name);

/**
* Unload a module
*/
void unload_module( struct mapper_instance *module );

/**
* compose mapper module chain
*/
struct mapper_listitem *load_mappers( scconf_context *ctx );

/**
* unload mapper module chain
*/
void unload_mappers(void);

/*
* this function search mapper module list until
* find a module that returns a login name for
* provided certificate
*/
char * find_user(X509 *x509);

/**
* This function search mapper module list until
* find a module that match provided login name
* if login is null, call find_user and returns 1,or 0 depending on user found
* @return 1 if match
*         0 on no match
*         -1 on error
*/
int match_user(X509 *x509, const char *login);

/*
* This funcions goest throught the mapper list
* and trying to get the certificate strings to be used on each
* module to perform find/match functions. 
* No map / match are done: just print found strings on stdout.
* This function is mostly used in pkcert_view toool
*/
void inspect_certificate(X509 *x509);

#endif
