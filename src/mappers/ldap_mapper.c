/*
 * PAM-PKCS11 ldap mapper module
 * Copyright (C) 2005 Dominik Fischer <dom_fischer@web.de>
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
 * pam-pkcs11 is copyright (C) 2003-2004 of Mario Strasser <mast@gmx.net>
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * $Id$
 */

/*
 * Sandro Wefel (SaW) <sandro.wefel@informatik.uni-halle.de> added
 *  TLS/SSL support (see autofs-ldap and libnss-ldap)
 *  multiple LDAP-Server support
 *  multi-value certificate entries
 */

#define __LDAP_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* FIXME do not use deprecated ldap_* functions */
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <pwd.h>
#include <openssl/x509.h>

#include "../common/cert_st.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../scconf/scconf.h"
#include "../common/strings.h"
#include "../common/cert_info.h"

#include "mapper.h"
#include "ldap_mapper.h"

/*
* This mapper uses the "login" parameter from mapper_match_user and
* uses it to get a certificate from a LDAP server. The digest of
* this certificate is then compared to the digest of the certificate
* from smartcard.
* Configuration is done in pam_pkcs11.conf.
*/


static const int LDAP_CONFIG_URI_MAX = 10;


/*
 * TODO: 
 * - Support for SASL-AUTH not included yet, I can't test it
 *  
 * - ldap_unbind (*ld) crash if you connect to a SSL port but have set TLS intead SSL
 *   - no idea why!?
 *   - you got no error-massage from your application
 *   - believe skip ldap_unbind (*ld) for a bind handle isn't a good solution
 * 
 * - implement searchtimeout
 * - implement ignorecase
 */


enum ldap_ssl_options
{
  SSL_OFF,
  SSL_LDAPS,
  SSL_START_TLS
};

typedef enum ldap_ssl_options ldap_ssl_options_t;

#ifndef LDAPS_PORT
#define LDAPS_PORT 636
#endif 


/*** Internal vars *****************************************************/

/* Host and Port */
static const char *ldaphost="";
static int ldapport=0;
/* or URI (allow multiple hosts) */
static const char *ldapURI="";
static int scope=1; /* 0: LDAP_SCOPE_BASE, 1: LDAP_SCOPE_ONE, 2: LDAP_SCOPE_SUB */
static const char *binddn="";
static const char *passwd="";
static const char *base="ou=People,o=example,c=com";
static const char *attribute="userCertificate";
static const char *filter="(&(objectClass=posixAccount)(uid=%s)";
static int searchtimeout=20;
static int ignorecase=0;
static const X509 **ldap_x509;
static int certcnt=0;

static ldap_ssl_options_t ssl_on = SSL_OFF;
#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
/* TLS/SSL specific options */
static const char *tls_randfile="";
static const char *tls_cacertfile="";
static const char *tls_cacertdir="";
static int tls_checkpeer=-1;
static const char *tls_ciphers="";
static const char *tls_cert=""; 
static const char *tls_key="";
#endif

static int ldapVersion = 3;	 	
#ifdef HAVE_LDAP_SET_OPTION
static int timeout = 8;			/* 8 seconds */
#endif
static int bind_timelimit = 2; 	/* Timelimit for BIND */

static const int sscope[] = {
	LDAP_SCOPE_BASE, 
	LDAP_SCOPE_ONELEVEL, 
	LDAP_SCOPE_SUBTREE};

/*** Internal funcs ****************************************************/


static int do_init (LDAP ** ld, const char *uri, int ldapdefport)
{
	int rc;
	int ldaps;
	char uribuf[512];
	char *p;
	
	DBG("do_init():");

	ldaps = (strncasecmp (uri, "ldaps://", sizeof ("ldaps://") - 1) == 0);
	p = strchr (uri, ':');
	/* we should be looking for the second instance to find the port number */
	if (p != NULL)
	{
		p = strchr (p, ':');
	}

#ifdef HAVE_LDAP_INITIALIZE
	if (p == NULL &&
		((ldaps && ldapdefport != LDAPS_PORT) || (!ldaps && ldapdefport != LDAP_PORT)))
	{
		/* No port specified in URI and non-default port specified */
		snprintf (uribuf, sizeof (uribuf), "%s:%d", uri, ldapdefport);
		uri = uribuf;
	}
	rc = ldap_initialize (ld, uri);
#else
	/* TODO: !HAVE_LDAP_INITIALIZE => no ldaps:// possible? */
	if (strncasecmp (uri, "ldap://", sizeof ("ldap://") - 1) != 0)
    {
		return LDAP_UNAVAILABLE;
    }

	uri += sizeof ("ldap://") - 1;
	p = strchr (uri, ':');

	if (p != NULL)
    {
		size_t urilen = (p - uri);
		
		if (urilen >= sizeof (uribuf))
		{
			return LDAP_UNAVAILABLE;
		}
		
		memcpy (uribuf, uri, urilen);
		uribuf[urilen] = '\0';
		
		ldapdefport = atoi (p + 1);
		uri = uribuf;
	}

# ifdef HAVE_LDAP_INIT
	*ld = ldap_init (uri, ldapdefport);
# else
	*ld = ldap_open (uri, ldapdefport);
# endif
	rc = (*ld == NULL) ? LDAP_SERVER_DOWN : LDAP_SUCCESS;

#endif /* HAVE_LDAP_INITIALIZE */

	if (rc == LDAP_SUCCESS && *ld == NULL)
	{
	  	rc = LDAP_UNAVAILABLE;
	}
	return rc;
}


#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
/* 
 * Set the ssl option
 */
static int do_ssl_options (LDAP *ldap_connection)
{
	int rc;

	DBG("do_ssl_options");

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
	if (strncmp(tls_randfile,"",1))
	{

		/* rand file */
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_RANDOM_FILE,
		    tls_randfile);
		if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_RANDOM_FILE failed");
			return LDAP_OPERATIONS_ERROR;
		}
	}
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */

	if (strncmp(tls_cacertfile,"",1))
	{
		/* ca cert file */
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE,
			tls_cacertfile);
		if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTFILE failed");
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (strncmp(tls_cacertdir,"",1))
    {
		/* ca cert directory */
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR,
				    tls_cacertdir);
		if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTDIR failed");
			return LDAP_OPERATIONS_ERROR;
		}
    }

	/* the cert have to be checked ? */
	if (tls_checkpeer > -1)
	{
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
			&tls_checkpeer);
		if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_REQUIRE_CERT failed");
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (strncmp(tls_ciphers,"",1))
    {
		/* set cipher suite, certificate and private key: */
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
			tls_ciphers);
		if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_CIPHER_SUITE failed");
			return LDAP_OPERATIONS_ERROR;
		}
	}

	/* where is the requiered cert */
	if (strncmp(tls_cert,"",1))
    {
	    rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE, 
	    	tls_cert);
	    if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_CERTFILE failed");
			return LDAP_OPERATIONS_ERROR;
		}
    }

	/* where is the key */
	if (strncmp(tls_key,"",1))
	{
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE, 
			tls_key);
		if (rc != LDAP_SUCCESS)
		{
			DBG("do_ssl_options: Setting of LDAP_OPT_X_TLS_KEYFILE failed");
			return LDAP_OPERATIONS_ERROR;
		}
	}
	return LDAP_SUCCESS;
}
#endif


static int
do_bind (LDAP * ldap_connection, int timelimit)
{
	int rc;
	int rv;
	struct timeval tv;
	LDAPMessage *result;

	/*
	 * set timelimit in ld for select() call in ldap_pvt_connect() 
	 * function implemented in libldap2's os-ip.c
	 */
  	tv.tv_sec = timelimit;
  	tv.tv_usec = 0;

DBG2("do_bind(): bind DN=\"%s\" pass=\"%s\"",binddn,passwd);

  	/* LDAPv3 doesn't need bind at all, 
  	 * nevertheless, if no binddn is given than bind anonymous */
 	if ( ! strncmp(binddn,"",1) ) {
 		rv = ldap_simple_bind(ldap_connection, NULL, NULL);
 	} else {
		rv = ldap_simple_bind(ldap_connection, binddn, passwd);
 	}

	if (rv < 0)
	{
DBG("do_bind: rv < 0");
		
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
		if (ldap_get_option (ldap_connection, LDAP_OPT_ERROR_NUMBER, &rc) !=
            LDAP_SUCCESS)
		{
		  rc = LDAP_UNAVAILABLE;
		}
#else
		rc = ldap_connection->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */
		/* Notify if we failed. */
		DBG3("could not connect to LDAP server as %s - %d - %s",
		  binddn, rc, ldap_err2string (rc));

		return rc;
	}

	rc = ldap_result (ldap_connection, rv, 0, &tv, &result);
	if (rc > 0)
	{
DBG1("do_bind rc=%d", rc);
		/* debug ("<== do_bind"); */
		return ldap_result2error (ldap_connection, result, 1);
	}

	/* took too long */
	if (rc == 0)
	{
DBG("do_bind rc=0");
		
		ldap_abandon (ldap_connection, rv);
	}

DBG("do_bind return -1");
	return -1;
}

/*
 * Opes connection to an LDAP server
 * uri must be one URI
 */
static int do_open (LDAP **ld, const char* uri, int defport, ldap_ssl_options_t ssl_on_local)
{
	
#if defined(LDAP_OPT_NETWORK_TIMEOUT) || defined(HAVE_LDAP_START_TLS)	
	struct timeval tv;
#endif
#ifdef HAVE_LDAP_START_TLS
	struct timeval *tvp;
	LDAPMessage *res = NULL;
	int msgid;
#endif	
	int rc;

	rc = do_init (ld, uri, defport);
	
	if (rc != LDAP_SUCCESS)
	{
		DBG("do_open(): do_init failed");
		return rc;
    }

	if( ! *ld)
	{
		DBG("do_open(): internal error - assert (*ld != NULL)");
		return(-2);
	}

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
	ldap_set_option (*ld, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
#endif /* LDAP_OPT_PROTOCOL_VERSION */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_NETWORK_TIMEOUT)
/*	ldap_set_option (*ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout); */

	rc = ldap_set_option(*ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
	if ( rc != LDAP_SUCCESS ) {
		DBG2("Warning: failed to set connection timeout to %d: %s", timeout, ldap_err2string(rc));
	} else
		DBG1("Set connection timeout to %d", timeout);
#endif /* LDAP_OPT_NETWORK_TIMEOUT */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_NETWORK_TIMEOUT)
	tv.tv_sec = bind_timelimit;
	tv.tv_usec = 0;
	ldap_set_option (*ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#endif /* LDAP_OPT_NETWORK_TIMEOUT */


#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
	if (ssl_on_local == SSL_START_TLS)
    {
		int version;

		/* we need V3 at least */
		if (ldap_get_option(*ld, LDAP_OPT_PROTOCOL_VERSION,
							&version) == LDAP_OPT_SUCCESS)
		{
			if (ldapVersion < LDAP_VERSION3)
			{
				ldapVersion = LDAP_VERSION3;
				ldap_set_option (*ld, LDAP_OPT_PROTOCOL_VERSION,
			    			&ldapVersion);
	    	}
		}

		/* set up SSL context */
		if (do_ssl_options (*ld) != LDAP_SUCCESS)
		{
			ldap_unbind (*ld);
			DBG("do_open(): SSL setup failed");
			return LDAP_UNAVAILABLE;
		}

#ifdef HAVE_LDAP_START_TLS

  		DBG("do_open(): do_start_tls");
		rc = ldap_start_tls (*ld, NULL, NULL, &msgid);
		if (rc != LDAP_SUCCESS)
		{
		  DBG1("do_open(): ldap_start_tls failed: %s", ldap_err2string (rc));
		  return rc;
		}

		if (bind_timelimit == LDAP_NO_LIMIT)
		{
			tvp = NULL;
    	}
  		else
    	{
      		tv.tv_sec = bind_timelimit;
      		tv.tv_usec = 0;
      		tvp = &tv;
    	}

		rc = ldap_result (*ld, msgid, 1, tvp, &res);
		if (rc == -1)
		{
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
			if (ldap_get_option (*ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
			{
				rc = LDAP_UNAVAILABLE;
			}
#else
			rc = ld->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */

			DBG1("do_open(): ldap_start_tls failed: %s", ldap_err2string (rc));
			return rc;
		}

		rc = ldap_result2error (*ld, res, 1);
		if (rc != LDAP_SUCCESS)
		{
			DBG1("do_open(): ldap_result2error failed: %s)", ldap_err2string (rc));
			return rc;
		}

		rc = ldap_install_tls (*ld);
#else
		rc = ldap_start_tls_s (*ld, NULL, NULL);
#endif /* HAVE_LDAP_START_TLS */

  		if (rc == LDAP_SUCCESS)
		{
  			DBG("do_open(): TLS startup succeeded");
		}
		else
		{
			ldap_unbind (*ld);
			DBG2("do_open(): TLS startup failed for LDAP server %s: %s",
			     uri, ldap_err2string (rc));
		    return rc;
		}
	}
  	else
#endif /* HAVE_LDAP_START_TLS_S || HAVE_LDAP_START_TLS */

	/*
	 * If SSL is desired, then enable it.
	 */
	if (ssl_on_local == SSL_LDAPS)
    {
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
		int tls = LDAP_OPT_X_TLS_HARD;
		if (ldap_set_option (*ld, LDAP_OPT_X_TLS, &tls) !=
			LDAP_SUCCESS)
		{
			ldap_unbind (*ld);
			DBG("do_open(): TLS setup failed");
			return LDAP_UNAVAILABLE;
		}

		/* set up SSL context */
		if (do_ssl_options (*ld) != LDAP_SUCCESS)
		{
			ldap_unbind (*ld);
			DBG("do_open(): SSL setup failed");
			return LDAP_UNAVAILABLE;
		}
#endif		
    }
	
	rc = do_bind (*ld, bind_timelimit);
	if (rc != LDAP_SUCCESS)
	{
		DBG2("do_open(): failed to bind to LDAP server %s: %s",
			 uri, ldap_err2string (rc));
		ldap_unbind (*ld);
	}
	return rc;
}

/*
 * add singe URI to array of uris
 */
static int ldap_add_uri (char **uris, const char *a_uri, char **buffer, size_t *buflen)
{
	int i;
	size_t uri_len;

  	for (i = 0; uris[i] != NULL; i++)
    ;

	if (i == LDAP_CONFIG_URI_MAX)
	{
		DBG("maximum number of URIs exceeded");
		return -1;
	}

	uri_len = strlen (a_uri);

  	if (*buflen < uri_len + 1)
  	{
		DBG("buffer to small for URI");
		return -1;
  	}

	memcpy (*buffer, a_uri, uri_len + 1);

	uris[i] = *buffer;
	uris[i + 1] = NULL;

	*buffer += uri_len + 1;
	*buflen -= uri_len + 1;

	DBG1("added URI %s", a_uri);

  	return 0;
}



/**
* Get certificate from LDAP-Server.
*/
static int ldap_get_certificate(const char *login) {
	LDAP *ldap_connection;
	int ret, entries;
	LDAPMessage *res;
	LDAPMessage *entry;
	struct berval **bvals = NULL;
	BerElement *ber = NULL;
	char *name = NULL;
	char filter_str[100];
	char *attrs[2];
	int rv;
	void *bv_val;

	char uri[4096];
	char uribuf[4096];
	char *uris[LDAP_CONFIG_URI_MAX + 1];
	const char *p;
	int current_uri = 0, start_uri = 0;

	char *buffer;
	size_t buflen;

	uris[0] = NULL;

	attrs[0] = (char *)attribute;
	attrs[1] = NULL;

	DBG1("ldap_get_certificate(): begin login = %s", login);

	/* Put the login to the %s in Filterstring */
	snprintf(filter_str, sizeof(filter_str), filter, login); 

	DBG1("ldap_get_certificate(): filter_str = %s", filter_str);
	
	/* parse and split URI config entry */
	buffer = uribuf;
	buflen = sizeof (uribuf);

	strncpy(uri, ldapURI, sizeof (uri)-1);

	/* Add a space separated list of URIs */
	/* TODO: no spaces in one URI allowed => URL-encoding? */
	if(strncmp(ldapURI,"",1))
		for (p = uri; p != NULL; )
		{
			char *q = strchr (p, ' ');
			if (q != NULL)
				*q = '\0';
			
			if( strlen(p) > 1 ) /* SAW: don't add spaces */
				rv = ldap_add_uri (uris, p, &buffer, &buflen);
			
			p = (q != NULL) ? ++q : NULL;
			
			if (rv)
				break;
		}
    /* set the default port if no port is given */
  	if (ldapport == 0)
    {
		if (ssl_on == SSL_LDAPS)
		{
		  ldapport = LDAPS_PORT;
		}
		else
		{
		  ldapport = LDAP_PORT;
		}
	}

	/* add ldaphost to uris if set, nevermind "uri" is set in config */
	if( strlen(ldaphost) > 1 )
	{
		/* No port specified in URI and non-default port specified */
		snprintf (uri, sizeof (uri), "%s%s:%d", 
		       ssl_on == SSL_LDAPS ? "ldaps://" : "ldap://",
		       ldaphost, ldapport);
		rv = ldap_add_uri (uris, uri, &buffer, &buflen);
	}

  	if (uris[0] == NULL)
    {
		DBG("ldap_get_certificate(): Nor URI or useable Host entry found");
		return(-1);
    }
	
	/* Attempt to connect to specified URI in order until do_open succeed */
	start_uri = current_uri;
	do
	{
		if(uris[current_uri] != NULL)
			DBG1("ldap_get_certificate(): try do_open for %s", uris[current_uri]);
		rv = do_open(&ldap_connection, uris[current_uri], ldapport, ssl_on);
		/* hot-fix, because in some circumstances an LDAP_SERVER_DOWN is returned */
		if (rv != LDAP_UNAVAILABLE && rv != LDAP_SERVER_DOWN)
			break;
		current_uri++;
		
		if (uris[current_uri] == NULL)
			current_uri = 0;
	}
	while (current_uri != start_uri);
	
	if( rv != LDAP_SUCCESS )
	{
		DBG("ldap_get_certificate(): do_open failed");
		return(-2);
	}

	/* TODO: (1) The problem: if an working uri is found it is used
    	     and if there is an (SSL-)error, no other one is tried
    	     (2) There is no session, so we don't know which LDAP_Server
    	     is the last with a successful connection. So we try the same
    	     server again. Perhaps create a state file/smem/etc. ?
    */

	rv = ldap_search_s(
				ldap_connection, 
				base, 
				sscope[scope], 
				filter_str, 
				attrs, 
				0, 
				&res);
	if ( rv != LDAP_SUCCESS ) {
		DBG1("ldap_search_s() failed: %s", ldap_err2string(rv));
		ldap_unbind_s(ldap_connection);
		return(-3);
	} else {
		entries = ldap_count_entries(ldap_connection, res);
		DBG1("ldap_get_certificate(): entries = %d", entries);

		if( entries > 1 ) {
			DBG("!  Warning, more than one entry found. Please choose \"filter\" and"); 
			DBG("!  \"attribute\" in ldap mapper config section of your config,");
			DBG("!  that only one entry with one attribute is matched");
			DBG("!  Maybe there is an other problem in ldap with not unique user");
			DBG("!  entries in your LDAP server.");
		}
				
		/* Only first entry is used. "filter" and "attribute" 
		 *  should be choosen, so that only one entry with
		 * one attribute is returned */
		if ( NULL == (entry = ldap_first_entry(ldap_connection, res))){
			DBG("ldap_first_entry() failed: %s");
			ldap_unbind_s(ldap_connection);
			return(-4);
		}

		/* Only first attribute is used. See comment above... */
		if ( NULL == (name = ldap_first_attribute(ldap_connection, res, &ber))){
			DBG("ldap_first_attribute() failed (rc=%d)");
			ldap_unbind_s(ldap_connection);
			return(-5);
		}
		DBG1("attribute name = %s", name);

		bvals = ldap_get_values_len(ldap_connection, entry, name);
		certcnt = ldap_count_values_len(bvals);

		DBG1("number of user certificates = %d", certcnt);
	
		ldap_x509 = malloc(sizeof(X509*) * certcnt );
		if (NULL == ldap_x509)
		{
			DBG("not enough memory");
			return(-7);
		}
		
		rv = 0;
		while(rv < certcnt )
		{
			/* SaW: not nifty, but otherwise gcc doesn't optimize */
			bv_val = &bvals[rv]->bv_val;
			ldap_x509[rv] = d2i_X509(NULL, ((const unsigned char **) bv_val), bvals[rv]->bv_len);
			if (NULL == ldap_x509) {
				DBG1("d2i_X509() failed for certificate %d", rv);
				free(ldap_x509);				
				certcnt=0;
				ldap_msgfree(res);
				ldap_unbind_s(ldap_connection);
				return(-6);
			}else {
				DBG1("d2i_X509(): success for certificate %d", rv);
			}
			rv++;
		}
		ldap_msgfree(res);
		/* TODO: this leads to a segfault, but the doc said ... */
		/* ldap_value_free_len(bvals); */
	}
	if ( 0 != (ret = ldap_unbind_s(ldap_connection))) {
		DBG("ldap_unbind_s() failed.");
		ldap_perror(ldap_connection, "ldap_unbind_s() failed.");
		return(-1);
	};

	DBG("ldap_get_certificate(): end");
	return 1;
}

static int read_config(scconf_block *blk) {
	int debug = scconf_get_bool(blk,"debug",0);
	const char *ssltls;

	ldaphost = scconf_get_str(blk,"ldaphost",ldaphost);
	ldapport = scconf_get_int(blk,"ldapport",ldapport);
	ldapURI = scconf_get_str(blk,"uri",ldapURI);
	scope = scconf_get_int(blk,"scope",scope);
	binddn = scconf_get_str(blk,"binddn",binddn);
	passwd = scconf_get_str(blk,"passwd",passwd);
	base = scconf_get_str(blk,"base",base);
	attribute = scconf_get_str(blk,"attribute",attribute);
	filter = scconf_get_str(blk,"filter",filter);
	ignorecase = scconf_get_bool(blk,"ignorecase",ignorecase);
	searchtimeout = scconf_get_int(blk,"searchtimeout",searchtimeout);

	ssltls =  scconf_get_str(blk,"ssl","off");
	if (! strncasecmp (ssltls, "tls", 3)) 
		ssl_on = SSL_START_TLS;
	else if( ! strncasecmp (ssltls, "on", 2))
		ssl_on = SSL_LDAPS;
	else if( ! strncasecmp (ssltls, "ssl", 3))
		ssl_on = SSL_LDAPS;
		
#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
	/* TLS specific options */
	tls_randfile = scconf_get_str(blk,"tls_randfile",tls_randfile);
	tls_cacertfile = scconf_get_str(blk,"tls_cacertfile",tls_cacertfile);
	tls_cacertdir = scconf_get_str(blk,"tls_cacertdir",tls_cacertdir);
	tls_checkpeer=scconf_get_int(blk,"tls_checkpeer",tls_checkpeer);
	tls_ciphers = scconf_get_str(blk,"tls_ciphers",tls_ciphers);
	tls_cert = scconf_get_str(blk,"tls_cert",tls_cert); 
	tls_key = scconf_get_str(blk,"tls_key",tls_key);
#endif


	set_debug_level(debug);
DBG1("test ssltls = %s", ssltls);

	DBG("LDAP mapper started.");
	DBG1("debug         = %d", debug);
	DBG1("ignorecase    = %d", ignorecase);
	DBG1("ldaphost      = %s", ldaphost);
	DBG1("ldapport      = %d", ldapport);
	DBG1("ldapURI       = %s", ldapURI);
	DBG1("scope         = %d", scope);
	DBG1("binddn        = %s", binddn);
	DBG1("passwd        = %s", passwd);
	DBG1("base          = %s", base);
	DBG1("attribute     = %s", attribute);
	DBG1("filter        = %s", filter);
	DBG1("searchtimeout = %d", searchtimeout);
	DBG1("ssl_on        = %d", ssl_on);
#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
	DBG1("tls_randfile  = %s", tls_randfile);
	DBG1("tls_cacertfile= %s", tls_cacertfile);
	DBG1("tls_cacertdir = %s", tls_cacertdir);
	DBG1("tls_checkpeer = %d", tls_checkpeer);
	DBG1("tls_ciphers   = %s", tls_ciphers);
	DBG1("tls_cert      = %s", tls_cert); 
	DBG1("tls_key       = %s", tls_key);	
#endif
	return 1;

}

_DEFAULT_MAPPER_END

static char ** ldap_mapper_find_entries(X509 *x509, void *context) {
        char **entries= cert_info(x509,CERT_PEM,ALGORITHM_NULL);
        if (!entries) {
                DBG("get_certificate() failed");
                return NULL;
        }
        return entries;
}

static int ldap_mapper_match_user(X509 *x509, const char *login, void *context) {
	int match_found = 0;
	int i=0;

	if ( 1 != ldap_get_certificate(login)){
		DBG("ldap_get_certificate() failed");
		match_found = 0;
	} else {
		/* TODO: maybe compare public keys instead of hashes */
		while( i<certcnt && !match_found ) {
#ifdef HAVE_NSS
			if ( x509 == ldap_x509[i]) {
#else
			if ( 0 == X509_cmp(x509, ldap_x509[i])) {
#endif
				DBG1("Certificate %d is matching", i);
				match_found = 1;
			} else { 
				DBG1("Certificate %d is NOT matching", i);
			}
			i++;
		}
		if (certcnt) 
			free(ldap_x509);
		certcnt=0;
	}
	return match_found;
}

static char * ldap_mapper_find_user(X509 *x509, void *context) {
	struct passwd *pw = NULL;
	char *found=NULL;
	setpwent();
	while( (pw=getpwent()) !=NULL) {
	    int res;
	    DBG1("Trying to match certificate with user: '%s'",pw->pw_name);
	    res= ldap_mapper_match_user(x509,pw->pw_name,context);
	    if (res) {
		DBG1("Certificate maps to user '%s'",pw->pw_name);
		found= clone_str(pw->pw_name);
		break;
	    } else {
		DBG1("Certificate map to user '%s' failed",pw->pw_name);
	    }
	}
	endpwent();

#ifdef false
	int res;	
	res= ldap_mapper_match_user(x509,"wefel",context);
	if (res) {
			DBG("Certificate maps to user wefel");
			found= clone_str("wefel");
	} else {
			DBG("Certificate map to user wefel failed");
	}
#endif
	
	return found;
}

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = ldap_mapper_find_entries;
	pt->finder = ldap_mapper_find_user;
	pt->matcher = ldap_mapper_match_user;
	pt->deinit = mapper_module_end;

	return pt;
}

#ifndef LDAP_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *mapper_name) {
#else
mapper_module * ldap_mapper_module_init(scconf_block *blk,const char *mapper_name) {
#endif
	mapper_module *pt;

    pt = init_mapper_st(blk,mapper_name);

	if (blk) {
		read_config(blk);
	} else {
		set_debug_level(1);
		DBG1("No configuration entry for mapper '%s'. Assume defaults", mapper_name);
	}
    return pt;
}
