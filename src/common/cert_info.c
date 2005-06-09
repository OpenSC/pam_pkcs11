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

#ifndef _CERT_INFO_C
#define _CERT_INFO_C

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "debug.h"
#include "error.h"
#include "strings.h"
#include "cert_info.h"

#if OPENSSL_VERSION_NUMBER >=  0x00907000L
#define UID_TYPE NID_x500UniqueIdentifier
#else
#define UID_TYPE NID_uniqueIdentifier
#endif

/*
* Extract Certificate's Common Name
*/
static char **cert_info_cn(X509 *x509) {
	static char *results[CERT_INFO_SIZE];
	int lastpos,position;
        X509_NAME *name = X509_get_subject_name(x509);
        if (!name) {
		DBG("Certificate has no subject");
		return NULL;
	}
	for (position=0;position<CERT_INFO_SIZE;position++) results[position]= NULL;
	position=0;
	lastpos = X509_NAME_get_index_by_NID(name,NID_commonName,-1);
	if (lastpos == -1) {
		DBG("Certificate has no UniqueID");
		return NULL;
	}
	while( ( lastpos != -1 ) && (position<CERT_INFO_MAX_ENTRIES) ) {
	    X509_NAME_ENTRY *entry;
	    ASN1_STRING *str;
	    unsigned char *txt;
	    if ( !(entry = X509_NAME_get_entry(name,lastpos)) ) {
                DBG1("X509_get_name_entry() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                return results;
            }
	    if ( !(str = X509_NAME_ENTRY_get_data(entry)) ) {
                DBG1("X509_NAME_ENTRY_get_data() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                return results;
            }
            if ( ( ASN1_STRING_to_UTF8(&txt, str) ) < 0) {
                DBG1("ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                return results;
            }
	    DBG2("%s = [%s]", OBJ_nid2sn(NID_commonName), txt);
	    results[position++]=clone_str((const char *)txt);
	    OPENSSL_free(txt);
	    lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, lastpos);
	}
	/* no more UID's availables in certificate */
	return results;
}

/*
* Extract Certificate's Subject
*/
static char **cert_info_subject(X509 *x509) {
	X509_NAME *subject;
	static char *entries[2] = { NULL, NULL };
	entries[0] = malloc(256);
	if (!entries[0]) return NULL;
        subject = X509_get_subject_name(x509);
        if (!subject) {
                DBG("X509_get_subject_name failed");
                return NULL;
        }
        X509_NAME_oneline(subject, entries[0], 256 );
	return entries;
}

/*
* Extract Certificate's Kerberos Principal Name
*/
static char **cert_info_kpn(X509 *x509) {
        int i,j;
	static char *entries[CERT_INFO_SIZE];
        STACK_OF(GENERAL_NAME) *gens;
        GENERAL_NAME *name;
        ASN1_OBJECT *krb5PrincipalName;
        DBG("Trying to find a Kerberos Principal Name in certificate");
        gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
        krb5PrincipalName = OBJ_txt2obj("1.3.6.1.5.2.2", 1);
        if (!gens) {
                DBG("No alternate name extensions");
                return NULL; /* no alternate names */
        }
        if (!krb5PrincipalName) {
                DBG("Cannot map KPN object");
                return NULL;
        }
	for (j=0;j<CERT_INFO_SIZE;j++) entries[j] = NULL;
        for (i=0,j=0; (i < sk_GENERAL_NAME_num(gens)) && (j<CERT_INFO_MAX_ENTRIES); i++) {
            name = sk_GENERAL_NAME_value(gens, i);
            if ( name && name->type==GEN_OTHERNAME ) {  /* test for UPN */
                if (OBJ_cmp(name->d.otherName->type_id, krb5PrincipalName)) continue; /* object is not a UPN */
		else {
		    /* NOTE: 
		    from PKINIT RFC, I deduce that stored format for kerberos
		    Principal Name is ASN1_STRING, but not sure at 100%
		    Any help will be granted
		    */
		    unsigned char *txt;
		    ASN1_TYPE *val = name->d.otherName->value;
		    ASN1_STRING *str= val->value.asn1_string;
                    DBG("Found Kerberos Principal Name ");
		    if ( ( ASN1_STRING_to_UTF8(&txt, str) ) < 0) {
                        DBG1("ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                    } else {
                        DBG1("Adding KPN entry: %s",txt);
		        entries[j++]= clone_str((const char *)txt);
		    }
		}
            }
        }
        sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
        ASN1_OBJECT_free(krb5PrincipalName);
	if(j==0) {
            DBG("Certificate does not contain a KPN entry");
	    return NULL;
	}
	return entries;
}

/*
* Extract Certificate's email
*/
static char **cert_info_email(X509 *x509) {
        int i,j;
	static char *entries[CERT_INFO_SIZE];
	STACK_OF(GENERAL_NAME) *gens;
        GENERAL_NAME *name;
        DBG("Trying to find an email in certificate");
        gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
        if (!gens) {
                DBG("No alternate name(s) in certificate");
                return 0; /* no alternate names */
        }
        for (i=0,j=0; (i < sk_GENERAL_NAME_num(gens)) && (j<CERT_INFO_MAX_ENTRIES); i++) {
            name = sk_GENERAL_NAME_value(gens, i);
            if ( name && name->type==GEN_EMAIL ) {
                DBG1("Found E-Mail Entry = '%s'", name->d.ia5->data);
		entries[j++]=clone_str((const char *)name->d.ia5->data);
            }
        }
        sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	if(j==0) {
            DBG("Certificate does not contain a Email entry");
	    return NULL;
	}
	return entries;
}

/*
* Extract Certificate's Microsoft Universal Principal Name
*/
static char **cert_info_upn(X509 *x509) {
        int i,j;
	static char *entries[CERT_INFO_SIZE];
        STACK_OF(GENERAL_NAME) *gens;
        GENERAL_NAME *name;
        DBG("Trying to find an Universal Principal Name in certificate");
        gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
        if (!gens) {
	    DBG("No alternate name extensions found");
	    return NULL;
	}
	for (j=0;j<CERT_INFO_SIZE;j++) entries[j] = NULL;
        for (i=0,j=0; (i < sk_GENERAL_NAME_num(gens)) && (j<CERT_INFO_MAX_ENTRIES); i++) {
            name = sk_GENERAL_NAME_value(gens, i);
            if ( name && name->type==GEN_OTHERNAME ) {
                /* test for UPN */
                if (OBJ_cmp(name->d.otherName->type_id, OBJ_nid2obj(NID_ms_upn))) continue; /* object is not a UPN */
                DBG("Found MS Universal Principal Name ");
                /* try to extract string and return it */
                if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
                    ASN1_UTF8STRING *str = name->d.otherName->value->value.utf8string;
                    DBG1("Adding UPN NAME entry= %s",str->data);
		    entries[j++] = clone_str((const char *)str->data);
                } else {
		    DBG("Found UPN entry is not an utf8string");
		}
            }
        }
        sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	if(j==0) {
            DBG("Certificate does not contain a MS UPN entry");
	    return NULL;
	}
	return entries;
}

/*
* Extract Certificate's Unique Identifier(s)
* Array size is limited to CERT_INFO_MAX_ENTRIES UID's. expected to be enought...
*/
static char **cert_info_uid(X509 *x509) {
	static char *results[CERT_INFO_SIZE];
	int lastpos,position;
        X509_NAME *name = X509_get_subject_name(x509);
        if (!name) {
		DBG("Certificate has no subject");
		return NULL;
	}
	for (position=0;position<CERT_INFO_SIZE;position++) results[position]= NULL;
	position=0;
	lastpos = X509_NAME_get_index_by_NID(name,UID_TYPE,-1);
	if (lastpos == -1) {
		DBG("Certificate has no UniqueID");
		return NULL;
	}
	while( ( lastpos != -1 ) && (position<CERT_INFO_MAX_ENTRIES) ) {
	    X509_NAME_ENTRY *entry;
	    ASN1_STRING *str;
	    unsigned char *txt;
	    if ( !(entry = X509_NAME_get_entry(name,lastpos)) ) {
                DBG1("X509_get_name_entry() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                return results;
            }
	    if ( !(str = X509_NAME_ENTRY_get_data(entry)) ) {
                DBG1("X509_NAME_ENTRY_get_data() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                return results;
            }
            if ( ( ASN1_STRING_to_UTF8(&txt, str) ) < 0) {
                DBG1("ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(),NULL));
                return results;
            }
	    DBG2("%s = [%s]", OBJ_nid2sn(UID_TYPE), txt);
	    results[position++]=clone_str((const char *)txt);
	    OPENSSL_free(txt);
	    lastpos = X509_NAME_get_index_by_NID(name, UID_TYPE, lastpos);
	}
	/* no more UID's availables in certificate */
	return results;
}

/* convert publickey into PEM format */
static char *key2pem(EVP_PKEY *key) {
	int len;
	char *pt,*res;
	BIO *buf= BIO_new(BIO_s_mem());
	if (!buf) {
	    DBG("BIO_new() failed");
	    return NULL;
	}
	if ( ! PEM_write_bio_PUBKEY(buf,key) ) {
	    DBG("Cannot print public key");
	    return NULL;
	}
	/* extract data */
	len= BIO_get_mem_data(buf,&pt);
	if( !(res=malloc(len+1)) ) {
	    DBG("Cannot malloc() to copy public key");
	    return NULL;
	}
	memcpy(res,pt,len);
	*(res+len)='\0';
	/*BIO_set_close(buf,BIO_NOCLOSE); */
	BIO_free(buf);
	return res;
}

/*
* Extract Certificate's Public Key
*/
static char **cert_info_puk(X509 *x509) {
	int res;
	char *pt;
	static char *entries[2] = { NULL,NULL };
	EVP_PKEY *pubk = X509_get_pubkey(x509);
	if(!pubk) {
	    DBG("Cannot extract public key");
	    return NULL;
	}
	pt=key2pem(pubk);
	if (!pt) { 
	    DBG("key2pem() failed");
	    EVP_PKEY_free(pubk);
	    return NULL;
	}
	EVP_PKEY_free(pubk);
	DBG1("Public key is '%s'\n",pt);
	entries[0]=pt;
	return entries;
}

/*
* Extract Certificate's Public Key in OpenSSH format
*/
static char **cert_info_sshpuk(X509 *x509) {
	int res;
	char *pt,*buf;
	char *from,*to,*end;
	static char *entries[2] = { NULL,NULL };
	EVP_PKEY *pubk = X509_get_pubkey(x509);
	if(!pubk) {
	    DBG("Cannot extract public key");
	    return NULL;
	}
	pt=key2pem(pubk);
	/* malloc at least same length than received and test */
	if (!pt || !(buf=malloc(strlen(pt)) ) ) { 
	    DBG("key2pem() failed");
	    EVP_PKEY_free(pubk);
	    return NULL;
	}
	/* now compose data in openssh style */
	switch (pubk->type) {
		case EVP_PKEY_RSA: sprintf(buf,"ssh-rsa "); break;
		case EVP_PKEY_DSA: sprintf(buf,"ssh-dss "); break;
		default: DBG("Unknown public key type"); return NULL;
	}
	EVP_PKEY_free(pubk);
	/* TODO: convert pk to openssh format */
	to=buf+strlen(buf);
	from=1+strchr(pt,'\n'); /* skip BEGIN PUBLIC KEY block */
	end=strstr(pt,"-----END")-1;
	for(;from<end;from++) if (! isspace(*from) ) *to++=*from;
	*to='\0';
	DBG1("Public key is '%s'\n",buf);
	entries[0]=buf;
	return entries;
}

static char* get_fingerprint(X509 *cert,const EVP_MD *type) {
    unsigned char    md[EVP_MAX_MD_SIZE];
    unsigned int     len;
    X509_digest(cert,type,md,&len);
    if (!len) {
	DBG("X509_digest() failed");
	return NULL;
    }
    return bin2hex(md,len);
}

/*
* Evaluate Certificate Signature Digest
*/
static char **cert_info_digest(X509 *x509, const char *algorithm) {
	static char *entries[2] = { NULL,NULL };
	const EVP_MD *digest = EVP_get_digestbyname(algorithm);
        if(!digest) {
                digest= EVP_sha1();
                DBG1("Invalid digest algorithm %s, using 'sha1'",algorithm);
        }
	entries[0]= get_fingerprint(x509,digest);
	return entries;
}

/*
* Return certificate in PEM format
*/
static char **cert_info_pem(X509 *x509) {
	int len;
	char *pt,*res;
	static char *entries[2] = { NULL,NULL };
	BIO *buf= BIO_new(BIO_s_mem());
	if (!buf) {
	    DBG("BIO_new() failed");
	    return NULL;
	}
	if ( ! PEM_write_bio_X509(buf,x509) ) {
	    DBG("Cannot print certificate");
	    return NULL;
	}
	/* extract data */
	len= BIO_get_mem_data(buf,&pt);
	if ( ! (res= malloc(len+1) ) ) {
	    DBG("Cannot malloc() to copy certificate");
	    return NULL;
	}
	memcpy(res,pt,len);
	*(res+len)='\0';
	/*BIO_set_close(buf,BIO_NOCLOSE); */
	BIO_free(buf);
	entries[0]=res;
	return entries;
}

/**
* request info on certificate
* @param x509 	Certificate to parse
* @param type 	Information to retrieve
* @param algorithm Digest algoritm to use
* @return utf-8 string array with provided information
*/
char **cert_info(X509 *x509, int type, const char *algorithm ) {
	if (!x509) {
		DBG("Null certificate provided");
		return NULL;
	}
	switch (type) {
	    case CERT_CN      : /* Certificate Common Name */
		return cert_info_cn(x509);
	    case CERT_SUBJECT : /* Certificate subject */
		return cert_info_subject(x509);
	    case CERT_KPN     : /* Kerberos principal name */
		return cert_info_kpn(x509);
	    case CERT_EMAIL   : /* Certificate e-mail */
		return cert_info_email(x509);
	    case CERT_UPN     : /* Microsoft's Universal Principal Name */
		return cert_info_upn(x509);
	    case CERT_UID     : /* Certificate Unique Identifier */
		return cert_info_uid(x509);
	    case CERT_PUK     : /* Certificate Public Key */
		return cert_info_puk(x509);
	    case CERT_SSHPUK  : /* Certificate Public Key in OpenSSH format */
		return cert_info_sshpuk(x509);
	    case CERT_PEM  : /* Certificate in PEM format */
		return cert_info_pem(x509);
	    case CERT_DIGEST  : /* Certificate Signature Digest */
		if ( !algorithm ) {
		    DBG("Must specify digest algorithm");
		    return NULL;		
		}
		return cert_info_digest(x509,algorithm);
	    default           :
		DBG1("Invalid info type requested: %d",type);
		return NULL;
	}
	/* should not get here */
	return NULL;
}

#endif /* _CERT_INFO_C */
