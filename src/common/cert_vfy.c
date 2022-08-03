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
#include "debug.h"
#include "cert_vfy.h"

#ifdef HAVE_NSS

#include <cryptohi.h>
#include "cert.h"
#include "secutil.h"

int verify_certificate(X509 * x509, cert_policy *policy)
{
    SECStatus rv;
    CERTCertDBHandle *handle;

    handle = CERT_GetDefaultCertDB();

    /* NSS already check all the revocation info with OCSP and crls */
    DBG2("Verifying Cert: %s (%s)", x509->nickname, x509->subjectName);
    rv = CERT_VerifyCertNow(handle, x509, PR_TRUE, certUsageSSLClient,
		NULL);
    if (rv != SECSuccess) {
	DBG1("Couldn't verify Cert: %s", SECU_Strerror(PR_GetError()));
    }

    return rv == SECSuccess ? 1 : 0;
}

int verify_signature(X509 * x509, unsigned char *data, int data_length,
                     unsigned char **signature, unsigned long *signature_length)
{

  SECKEYPublicKey *key;
  SECOidTag algid;
  SECStatus rv;
  SECItem sig;

  /* grab the key */
  key = CERT_ExtractPublicKey(x509);
  if (key == NULL) {
	DBG1("Couldn't extract key from certificate: %s",
		SECU_Strerror(PR_GetError()));
	return -1;
  }
  /* shouldn't the algorithm be passed in? */
  algid = SEC_GetSignatureAlgorithmOidTag(key->keyType, SEC_OID_SHA1);

  sig.data = *signature;
  sig.len = *signature_length;
  rv = VFY_VerifyData(data, data_length, key, &sig, algid, NULL);
  if (rv != SECSuccess) {
	DBG1("Couldn't verify Signature: %s", SECU_Strerror(PR_GetError()));
  }
  SECKEY_DestroyPublicKey(key);
  return (rv == SECSuccess)? 0 : 1;
}

#else

#define __CERT_VFY_C_

#include <string.h>
#include "../common/pam-pkcs11-ossl-compat.h"
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include "error.h"
#include "base64.h"
#include "uri.h"

static X509_CRL *download_crl(const char *uri)
{
  int rv = 0;
  unsigned int i = 0, j = 0;
  unsigned char *data = NULL, *der = NULL;
  const unsigned char *p = NULL;
  size_t data_len = 0, der_len = 0;
  X509_CRL *crl = NULL;

  rv = get_from_uri(uri, &data, &data_len);
  if (rv != 0) {
    set_error("get_from_uri() failed: %s", get_error());
    return NULL;
  }
  /* convert base64 to der if needed */
  for (i = 0; i <= data_len - 24; i++) {
    if (!strncmp((const char *)&data[i], "-----BEGIN X509 CRL-----", 24))
      break;
  }
  for (j = 0; j <= data_len - 22; j++) {
    if (!strncmp((const char *)&data[j], "-----END X509 CRL-----", 22))
      break;
  }
  if (i <= data_len - 24 && j <= data_len - 22 && i < j) {
    /* base64 format */
    DBG("crl is base64 encoded");
    der_len = (j - i + 1);      /* roughly */
    der = malloc(der_len);
    if (der == NULL) {
      free(data);
      set_error("not enough free memory available");
      return NULL;
    }
    data[j] = 0;
    der_len = base64_decode((const char *)&data[i + 24], der, der_len);
    free(data);
    if (der_len <= 0) {
      set_error("invalid base64 (pem) format");
      return NULL;
    }
    p = der;
    crl = d2i_X509_CRL(NULL, &p, der_len);
    free(der);
  } else {
    /* der format */
    DBG("crl is der encoded");
    p = data;
    crl = d2i_X509_CRL(NULL, &p, data_len);
    free(data);
  }
  if (crl == NULL)
    set_error("d2i_X509_CRL() failed");
  return crl;
}

static int verify_crl(X509_CRL * crl, X509_STORE_CTX * ctx)
{
  int rv = 0;
  EVP_PKEY *pkey = NULL;
  X509 *issuer_cert = NULL;

  /* get issuer certificate */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  X509_OBJECT obj;
  rv = X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_CRL_get_issuer(crl), &obj);
  if (rv > 0) {
    issuer_cert = X509_OBJECT_get0_X509((&obj));
    X509_OBJECT_free_contents(&obj);
#else
  X509_OBJECT *obj = X509_OBJECT_new();
  rv = X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_CRL_get_issuer(crl), obj);
  if (rv > 0) {
    issuer_cert = X509_OBJECT_get0_X509(obj);
    X509_OBJECT_free(obj);
#endif
  } else {
    set_error("getting the certificate of the crl-issuer failed");
    return -1;
  }
  /* extract public key and verify signature */
  pkey = X509_get_pubkey(issuer_cert);

  if (pkey == NULL) {
    set_error("getting the issuer's public key failed");
    return -1;
  }
  rv = X509_CRL_verify(crl, pkey);
  EVP_PKEY_free(pkey);
  if (rv < 0) {
    set_error("X509_CRL_verify() failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  } else if (rv == 0) {
    DBG("crl is invalid");
    return 0;
  }
  /* compare update times */
  const ASN1_TIME *lastUpdate;
  const ASN1_TIME *nextUpdate;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  lastUpdate = X509_CRL_get_lastUpdate(crl);
  nextUpdate = X509_CRL_get_nextUpdate(crl);
#else
  lastUpdate = X509_CRL_get0_lastUpdate(crl);
  nextUpdate = X509_CRL_get0_nextUpdate(crl);
#endif
  rv = X509_cmp_current_time(lastUpdate);
  if (rv == 0) {
    set_error("crl has an invalid last update field");
    return -1;
  }
  if (rv > 0) {
    DBG("crl is not yet valid");
    return 0;
  }
  rv = X509_cmp_current_time(nextUpdate);
  if (rv == 0) {
    set_error("crl has an invalid next update field");
    return -1;
  }
  if (rv < 0) {
    DBG("crl has expired");
    return 0;
  }
  return 1;
}

/* the structure DIST_POINT_NAME_st has been changed from 0.9.6 to 0.9.7 */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#define GET_FULLNAME(a) a->name.fullname
#else
#define GET_FULLNAME(a) a->fullname
#endif

static int check_for_revocation(X509 * x509, X509_STORE_CTX * ctx, crl_policy_t policy)
{
  int rv = 0, i = 0, j = 0;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  X509_OBJECT obj;
#else
  X509_OBJECT *obj = X509_OBJECT_new();
#endif
  X509_REVOKED *rev = NULL;
  STACK_OF(DIST_POINT) * dist_points = NULL;
  DIST_POINT *point = NULL;
  GENERAL_NAME *name = NULL;
  X509_CRL *crl = NULL;
  X509 *x509_ca = NULL;
  int ret = 0;
  DBG1("crl policy: %d", policy);
  if (policy == CRLP_NONE) {
    /* NONE */
    DBG("no revocation-check performed");
    ret = 1;
    goto exit;
  } else if (policy == CRLP_AUTO) {
    /* AUTO -> first try it ONLINE then OFFLINE */
    rv = check_for_revocation(x509, ctx, CRLP_ONLINE);
    if (rv < 0) {
      DBG1("check_for_revocation() failed: %s", get_error());
      rv = check_for_revocation(x509, ctx, CRLP_OFFLINE);
    }
    ret = rv;
    goto exit;
  } else if (policy == CRLP_OFFLINE) {
    /* OFFLINE */
    DBG("looking for an dedicated local crl");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    rv = X509_STORE_get_by_subject(ctx, X509_LU_CRL, X509_get_issuer_name(x509), &obj);
    if (rv > 0) {
      crl = X509_OBJECT_get0_X509_CRL((&obj));
#else
    rv = X509_STORE_get_by_subject(ctx, X509_LU_CRL, X509_get_issuer_name(x509), obj);
    if (rv > 0) {
      crl = X509_OBJECT_get0_X509_CRL(obj);
#endif
    } else {
      set_error("no dedicated crl available");
      ret = -1;
      goto exit;
    }
  } else if (policy == CRLP_ONLINE) {
    /* ONLINE */
    DBG("extracting crl distribution points");
    dist_points = X509_get_ext_d2i(x509, NID_crl_distribution_points, NULL, NULL);
    if (dist_points == NULL) {
      /* if there is not crl distribution point in the certificate have a look at the ca certificate */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
      rv = X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_issuer_name(x509), &obj);
      if (rv > 0) {
        x509_ca = X509_OBJECT_get0_X509((&obj));
#else
      rv = X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_issuer_name(x509), obj);
      if (rv > 0) {
        x509_ca = X509_OBJECT_get0_X509(obj);
#endif
      } else {
        set_error("no dedicated ca certificate available");
        ret = -1;
        goto exit;
      }

      dist_points = X509_get_ext_d2i(x509_ca, NID_crl_distribution_points, NULL, NULL);
      if (dist_points == NULL) {
        set_error("neither the user nor the ca certificate does contain a crl distribution point");
        ret = -1;
        goto exit;
      }
    }
    crl = NULL;
    for (i = 0; i < sk_DIST_POINT_num(dist_points) && crl == NULL; i++) {
      point = sk_DIST_POINT_value(dist_points, i);
      /* until now, only fullName is supported */
      if (point->distpoint != NULL && GET_FULLNAME(point->distpoint) != NULL) {
        for (j = 0; j < sk_GENERAL_NAME_num(GET_FULLNAME(point->distpoint)); j++) {
          name = sk_GENERAL_NAME_value(GET_FULLNAME(point->distpoint), j);
          if (name != NULL && name->type == GEN_URI) {
            DBG1("downloading crl from %s", name->d.ia5->data);
            crl = download_crl((const char *)name->d.ia5->data);

            /*crl = download_crl("file:///home/mario/projects/pkcs11_login/tests/ca_crl_0.pem"); */
            /*crl = download_crl("http://www-t.zhwin.ch/ca/root_ca.crl"); */
            /*crl = download_crl("http://www.zhwin.ch/~sri/"); */
            /*crl = download_crl("ldap://directory.verisign.com:389/CN=VeriSign IECA, OU=IECA-3, OU=Contractor, OU=PKI, OU=DOD, O=U.S. Government, C=US?certificateRevocationList;binary"); */
            if (crl != NULL)
              break;
            else
              DBG1("download_crl() failed: %s", get_error());
          }
        }
      }
    }
    sk_DIST_POINT_pop_free(dist_points, DIST_POINT_free);
    if (crl == NULL) {
      set_error("downloading the crl failed for all distribution points");
      ret = -1;
      goto exit;
    }
  } else {
    set_error("policy %d is not supported", policy);
    ret = -1;
    goto exit;
  }
  /* verify the crl and check whether the certificate is revoked or not */
  DBG("verifying crl");
  rv = verify_crl(crl, ctx);
  if (rv < 0) {
    set_error("verify_crl() failed: %s", get_error());
    ret = -1;
    goto exit;
  } else if (rv == 0) {
    ret = 0;
    goto exit;
  }
  DBG("checking revocation");
  rv = X509_CRL_get0_by_cert(crl, &rev, x509);
  ret = (rv == 0);

exit:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) /* is this correct for older openssl? */
  X509_OBJECT_free_contents(&obj);
#else
  X509_OBJECT_free(obj);
#endif
  /* crl is being freed by caller X509_STORE_free */
  /* FIXME: Isn't it still okay to free the CRL here? */
  return ret;

}

static int add_hash( X509_LOOKUP *lookup, const char *dir) {
  int rv=0;
  rv = X509_LOOKUP_add_dir(lookup,dir, X509_FILETYPE_PEM);
  if (rv != 1) { /* load all hash links in PEM format */
    set_error("X509_LOOKUP_add_dir(PEM) failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  rv = X509_LOOKUP_add_dir(lookup, dir, X509_FILETYPE_ASN1);
  if (rv != 1) { /* load all hash links in ASN1 format */
    set_error("X509_LOOKUP_add_dir(ASN1) failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  return 1;
}

static int add_file( X509_LOOKUP *lookup, const char *file) {
  int rv=0;
  rv = X509_LOOKUP_load_file(lookup,file, X509_FILETYPE_PEM);
  if (rv == 1) return 1;
  DBG("File format is not PEM: trying ASN1");
  rv = X509_LOOKUP_load_file(lookup,file, X509_FILETYPE_ASN1);
  if(rv!=1) {
    set_error("X509_LOOKUP_load_file(ASN1) failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1; /* neither PEM nor ASN1 format: return error */
  }
  return 1;
}

static X509_STORE * setup_store(cert_policy *policy) {
  int rv = 0;
  X509_STORE *store = NULL;
  X509_LOOKUP *lookup = NULL;

  /* setup the x509 store to verify the certificate */
  store = X509_STORE_new();
  if (store == NULL) {
    set_error("X509_STORE_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  /* if needed add hash_dir lookup methods */
  if ( (is_dir(policy->ca_dir)>0) || (is_dir(policy->crl_dir)>0) ) {
    DBG("Adding hashdir lookup to x509_store");
    lookup = X509_STORE_add_lookup(store,X509_LOOKUP_hash_dir());
    if (!lookup) {
      X509_STORE_free(store);
      set_error("X509_STORE_add_lookup(hash_dir) failed: %s", ERR_error_string(ERR_get_error(), NULL));
      return NULL;
    }
  }
  /* add needed hash dir pathname entries */
  if ( (policy->ca_policy) && (is_dir(policy->ca_dir)>0) ) {
    const char *pt=policy->ca_dir;
    if ( strstr(pt,"file:///")) pt+=8; /* strip url if needed */
    DBG1("Adding hash dir '%s' to CACERT checks",policy->ca_dir);
    rv = add_hash( lookup, pt);
    if (rv<0) goto add_store_error;
  }
  if ( (policy->crl_policy!=CRLP_NONE) && (is_dir(policy->crl_dir)>0 ) ) {
    const char *pt=policy->crl_dir;
    if ( strstr(pt,"file:///")) pt+=8; /* strip url if needed */
    DBG1("Adding hash dir '%s' to CRL checks",policy->crl_dir);
    rv = add_hash( lookup, pt);
    if (rv<0) goto add_store_error;
  }

  /* if needed add file lookup methods */
  if ( (is_file(policy->ca_dir)>0) || (is_file(policy->crl_dir)>0) ) {
    DBG("Adding file lookup to x509_store");
    lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
    if (!lookup) {
      X509_STORE_free(store);
      set_error("X509_STORE_add_lookup(file) failed: %s", ERR_error_string(ERR_get_error(), NULL));
      return NULL;
    }
  }
  /* and add file entries to lookup */
  if ( (policy->ca_policy) && (is_file(policy->ca_dir)>0) ) {
    const char *pt=policy->ca_dir;
    if ( strstr(pt,"file:///")) pt+=8; /* strip url if needed */
    DBG1("Adding file '%s' to CACERT checks",policy->ca_dir);
    rv = add_file(lookup, pt);
    if (rv<0) goto add_store_error;
  }
  if ( (policy->crl_policy!=CRLP_NONE) && (is_file(policy->crl_dir)>0 ) ) {
    const char *pt=policy->crl_dir;
    if ( strstr(pt,"file:///")) pt+=8; /* strip url if needed */
    DBG1("Adding file '%s' to CRL checks",policy->crl_dir);
    rv = add_file(lookup, pt);
    if (rv<0) goto add_store_error;
  }
  return store;

add_store_error:
  DBG1("setup_store() error: '%s'",get_error());
  X509_LOOKUP_free(lookup);
  X509_STORE_free(store);
  return NULL;
}

/*
* @return -1 on error, 0 on verify failed, 1 on verify success
*/
int verify_certificate(X509 * x509, cert_policy *policy)
{
  int rv = 0;
  X509_STORE *store = NULL;
  X509_STORE_CTX *ctx = NULL;

  /* if neither ca nor crl check are requested skip */
  if ( (policy->ca_policy==0) && (policy->crl_policy==CRLP_NONE) ) {
	DBG("Neither CA nor CRL check requested. CertVrfy() skipped");
	return 1;
  }

  /* setup the x509 store to verify the certificate */
  store = setup_store(policy);
  if (store == NULL) {
    set_error("setup_store() failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  ctx = X509_STORE_CTX_new();
  if (ctx == NULL) {
    X509_STORE_free(store);
    set_error("X509_STORE_CTX_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  X509_STORE_CTX_init(ctx, store, x509, NULL);
#if 0
  X509_STORE_CTX_set_purpose(ctx, purpose);
#endif
  if (policy->ca_policy) {
  rv = X509_verify_cert(ctx);
  if (rv != 1) {
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    set_error("certificate is invalid: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
		switch (X509_STORE_CTX_get_error(ctx)) {
			case X509_V_ERR_CERT_HAS_EXPIRED:
				rv = -2;
				break;
			case X509_V_ERR_CERT_NOT_YET_VALID:
				rv = -3;
				break;
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				rv = -4;
				break;
			default:
				rv = 0;
				break;
		}
		return rv;
  } else {
    DBG("certificate is valid");
  }
  }

  /* verify whether the certificate was revoked or not */
  rv = check_for_revocation(x509, ctx, policy->crl_policy);
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  if (rv < 0) {
    set_error("check_for_revocation() failed: %s", get_error());
    return -1;
  } else if (rv == 0) {
    DBG("certificate has been revoked");
  } else {
    DBG("certificate has not been revoked");
  }
  return rv;
}

int verify_signature(X509 * x509, unsigned char *data, int data_length,
                     unsigned char **signature, unsigned long *signature_length)
{
  int rv = 0;
  EVP_PKEY *pubkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  ECDSA_SIG* ec_sig = NULL;
  int rs_len = 0;
  unsigned char *p = NULL;

  /* get the public-key */
  pubkey = X509_get_pubkey(x509);
  if (pubkey == NULL) {
    set_error("X509_get_pubkey() failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  DBG1("public key type: 0x%08x", EVP_PKEY_base_id(pubkey));
  DBG1("public key bits: 0x%08x", EVP_PKEY_bits(pubkey));

  if (EVP_PKEY_base_id(pubkey) == EVP_PKEY_EC) {
    // FIXME: Why not to use d2i_ECDSA_SIG() ???
    rs_len = *signature_length / 2;
    ec_sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(*signature, rs_len, NULL);
    BIGNUM *s = BN_bin2bn(*signature + rs_len, rs_len, NULL);
    if (!r || !s) {
        set_error("Unable to parse r+s EC signature numbers: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (1 != ECDSA_SIG_set0(ec_sig, r, s)) {
        set_error("Unable to write r+s numbers to the signature structure: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    *signature_length = i2d_ECDSA_SIG(ec_sig, &p);
    free(*signature);
    *signature = malloc(*signature_length);
    p = *signature;
    *signature_length = i2d_ECDSA_SIG(ec_sig, &p);
    ECDSA_SIG_free(ec_sig);
  }

  md_ctx = EVP_MD_CTX_new();
  /* verify the signature */
#ifdef USE_HASH_SHA1
  DBG("hashing with SHA1");
  EVP_VerifyInit(md_ctx, EVP_sha1());
#else
  DBG("hashing with SHA256");
  EVP_VerifyInit(md_ctx, EVP_sha256());
#endif
  EVP_VerifyUpdate(md_ctx, data, data_length);
  rv = EVP_VerifyFinal(md_ctx, *signature, *signature_length, pubkey);
  EVP_PKEY_free(pubkey);
  EVP_MD_CTX_free(md_ctx);
  if (rv != 1) {
    set_error("EVP_VerifyFinal() failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  DBG("signature is valid");
  return 0;
}
#endif
