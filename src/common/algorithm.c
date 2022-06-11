/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003-2004 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
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

#include <cert_st.h>
#include <alg_st.h>

#ifdef HAVE_NSS
ALGORITHM_TYPE Alg_get_alg_from_string(const char *hashString)
{
    /* sigh, we don't have any string to out conversion
     * it would be nice to at least search the oid table by
     * description */
    SECOidTag hashOIDTag;

    if (strcasecmp(hashString, "sha1") == 0) {
	hashOIDTag = SEC_OID_SHA1;
    } else if (strcasecmp(hashString, "md5") == 0) {
	hashOIDTag = SEC_OID_MD5;
    } else if (strcasecmp(hashString, "md2") == 0) {
	hashOIDTag = SEC_OID_MD2;
    } else if (strcasecmp(hashString, "sha512") == 0) {
	hashOIDTag = SEC_OID_SHA512;
    } else if (strcasecmp(hashString, "sha384") == 0) {
	hashOIDTag = SEC_OID_SHA384;
    } else if (strcasecmp(hashString, "sha256") == 0) {
	hashOIDTag = SEC_OID_SHA256;
    } else {
	hashOIDTag = ALGORITHM_NULL;
    }

    return hashOIDTag;
}

const ALGDIGEST *Alg_get_digest_by_name(ALGORITHM_TYPE hash)
{
    return HASH_GetHashObjectByOidTag(hash);
}

#else

ALGORITHM_TYPE Alg_get_alg_from_string(const char *hashString)
{
    const EVP_MD *digest = NULL;

    digest = EVP_get_digestbyname(hashString);
    if (!digest) {
	return ALGORITHM_NULL;
    }
    return hashString;
}

const ALGDIGEST *Alg_get_digest_by_name(ALGORITHM_TYPE hash)
{
    return EVP_get_digestbyname((char *)hash);
}
#endif

