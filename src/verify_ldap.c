/** @file verify_ldap.c
 * LDAP Verifier
 *
 * Verifies users against an LDAP server (or servers.)
 * 
 * $Id: verify_ldap.c,v 1.9 2002-07-12 00:00:02 jjminer Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */


#include "verify.h"

#ifdef ENABLE_LDAP

/* LibC */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* ldap - using OpenLDAP SDK or Netscape SDK */
#ifdef HAVE_LDAP_H
# include <ldap.h>
#endif /* HAVE_LDAP_H */

/* login cgi includes */
#include "index.cgi.h"
#include "pbc_myconfig.h"

/* Error logging! */
#include "pbc_logging.h"

/**
 * Generates the name for the config file key
 * @param prefix char *
 * @param suffix char *
 * @retval malloc()d string (must be free()d!)
 */
static char * gen_key( const char * prefix, char * suffix )
{
    char * result;
    size_t len;
    int num;

    if( prefix == NULL )
        prefix = "";

    if( suffix == NULL )
        suffix = "";

    /* Add 2, one for the \0 and one for a _ */
    len =  strlen(prefix) + strlen(suffix) + 7;

    result = calloc( len, sizeof(char) );

    num = snprintf( result, len, "ldap%s%s_%s", 
                    strlen(prefix) ? "_" : "",
                    prefix, suffix );

    if ( num >= len )
        return NULL;

    return result;

}

/**
 * Actually does an LDAP Bind
 * @param ld LDAP *
 * @param user char *
 * @param password char *
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int do_bind( LDAP *ld, char * user, const char * password, const char ** errstr )
{
    int rc;

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "do_bind: hello\n" );

    rc = ldap_simple_bind_s (ld, user, password );

    if ( rc != LDAP_SUCCESS) {
        pbc_log_activity(PBC_LOG_DEBUG_LOW, "do_bind: failed - %s\n", 
                         ldap_err2string(rc) );
        *errstr  = "Bind failed -- auth failed";
        return -1;
    } else {
        pbc_log_activity(PBC_LOG_DEBUG_LOW, "do_bind: bind successful\n" );
    }

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "do_bind: bye!\n" );

    return 0;
}

/**
 * Connects to an LDAP Server
 * @param ld LDAP **
 * @param ldap_port int
 * @param dn char *
 * @param pwd char *
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int ldap_connect( LDAP ** ld, 
			 char * ldap_uri, 
			 char * dn, 
			 char * pwd,
			 const char ** errstr ) 
{
    int rc;
    char *tmp_uri, *p;

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "ldap_connect: hello\n" );

    /*
     * Work around a bug in the OpenLDAP stuff that causes the init to fail when
     * there are things other than the server name in the URI.
     */
    
    tmp_uri = strdup( ldap_uri );
    p = strstr( tmp_uri, "//" );
    p += 2;
    p = strchr( p, '/' );
    p++;
    *p = '\0';

    /* lookup DN for username using an anonymous bind */
    rc = ldap_initialize(ld, tmp_uri);

    free( tmp_uri );

    if (rc != LDAP_SUCCESS || ld == NULL) {
        pbc_log_activity( PBC_LOG_DEBUG_VERBOSE,
                          "ldap_connect: LDAP Initialization error %d.\n", rc  );
        *errstr = "connection to ldap server failed -- auth failed";
        return -2;
    }

    rc = do_bind( *ld, dn, pwd, errstr );

    if( rc == -1 ) {
        /* Here a bind failing isn't catastrophic..  */
        pbc_log_activity(PBC_LOG_DEBUG_LOW, "ldap_connect: Bind Failed.\n"  );
        ldap_unbind(*ld);
        return -2;
    }

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "ldap_connect: bye!\n" );

    return 0;
}

/* Do the search, get the matching Dn. */
/* Careful!  You have to free() the dn!  */

/**
 * Gets the DN of an object.
 * @param ld LDAP *
 * @param searchbase char *
 * @param attr char *
 * @param val const char *
 * @param dn char ** - malloc()d (must be free()d)
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int get_dn( LDAP * ld, 
                   char * ldapuri,
                   char ** dn,
                   const char ** errstr )
{
    int err;
    int num_entries;
    

    LDAPMessage * results, * entry;
    LDAPURLDesc *ludp;

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "get_dn: hello\n" );

    *dn = NULL;

    if ( ldap_url_parse( ldapuri, &ludp ) ) {
        pbc_log_activity(PBC_LOG_ERROR, "Cannot parse \"%s\"\n", ldapuri  );
        *errstr = "System Error.  Contact your system administrator.";
        return -1;
    }

    err = ldap_search_s( ld, ludp->lud_dn, LDAP_SCOPE_SUBTREE,
                         ludp->lud_filter, NULL, 0, &results );

    if (err != LDAP_SUCCESS) {
        *errstr = "user not found -- auth failed";
        return -1;
    }

    num_entries = ldap_count_entries(ld, results);

    pbc_log_activity( PBC_LOG_DEBUG_VERBOSE, "get_dn: Found %d Entries\n",
                      num_entries );

    if (num_entries != 1) {
        ldap_msgfree(results);
        *errstr = "too many or no entries found -- auth failed";
        return -1;
    }

    entry = ldap_first_entry(ld, results);

    if (entry == NULL) {
        ldap_msgfree(results);
        *errstr = "error getting ldap entry -- auth failed";
        /* The server had something go wrong -- OK to try again. */
        return -2;
    }

    *dn = ldap_get_dn(ld, entry);

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "get_dn: Got DN: \"%s\"\n", *dn  );
    
    if (*dn == NULL) {
        ldap_msgfree(results);
#ifdef NETSCAPE_LDAP_SDK
        ldap_msgfree(entry);
#endif
        *errstr = "error getting ldap dn -- auth failed";
        /* Again not fatal, probably a server error. */
        return -2;
    }

    ldap_msgfree( results );
#ifdef NETSCAPE_LDAP_SDK
    ldap_msgfree( entry );
#endif

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "get_dn: bye!\n" );

    return 0;
}

/**
 * Actually verifies the user against the LDAP server
 * @param userid const char *
 * @param passwd const char *
 * @param service const char *
 * @param user_realm const char *
 * @param errstr const char **
 * @retval 0 on success, nonzero on failure
 */

static int ldap_v( const char *userid,
			  const char *passwd,
			  const char *service,
			  const char *user_realm,
			  struct credentials **creds,
			  const char **errstr) 
{
    int   got_error = -2;
    int   i = 0;

    char  **ldap_uri_list;
    char *key = NULL;

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "ldap_verifier: hello\n" );

    if (creds) *creds = NULL;

    key = gen_key(user_realm, "uri");
    ldap_uri_list = libpbc_config_getlist(key);
    free(key);

    if (service != NULL) {
        *errstr = "LDAP Verifier can't handle Service cleanly...";
        return -2;
    }

    if ( userid == NULL || strlen(userid) == 0 ) {
        *errstr = "Username MUST be specified.";
        return -2;
    }

    if ( passwd == NULL || strlen(passwd) == 0 ) {
        *errstr = "Password MUST be specified.";
        return -2;
    }

    while ( (got_error == -2)
            && (ldap_uri_list != NULL)
            && (ldap_uri_list[i] != NULL) ) {

        char *ldap_uri_in = ldap_uri_list[i];
        char *ldap_uri;
        int len, num;

        LDAP *ld = NULL;
        char  *user_dn = NULL;

        if ( strstr( ldap_uri_in, "%s" ) == NULL ) {
            /* The LDAP URI must contain a %s to hold the user name! */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        /* Something big enough to hold the uri, userid and a \0 */
        len = strlen(ldap_uri_in) + strlen(userid) + 1;
        ldap_uri = malloc( len );

        if ( ldap_uri == NULL ) {
            /* Ooops, out of memory! */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        num = snprintf( ldap_uri, len, ldap_uri_in, userid );

        if ( num >= len ) {
            /* Uhm, nearly overflowed the buffer.  We should freak. */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        pbc_log_activity( PBC_LOG_DEBUG_VERBOSE,
                          "ldap_verifier: uri: \"%s\"\n", ldap_uri );

        if (userid == NULL || passwd == NULL) {
            *errstr = "username or password is null -- auth failed";
            got_error = -1;
        }

        /*
         * The definately needs to be changed.  There will need to be a
         * "searching" login that we use to find the Dn.
         */
        got_error = ldap_connect( &ld, ldap_uri, NULL, NULL, errstr );
        if( got_error == 0 ) {

            got_error = get_dn( ld, ldap_uri, &user_dn, errstr );

            if( got_error == 0 && strlen(user_dn) ) {

                got_error = do_bind( ld, user_dn, passwd, errstr );

                if (got_error != 0)
                    *errstr = "couldn't bind as user -- auth failed";

                free(user_dn);
            }
            /* close ldap connection */
            ldap_unbind(ld);
        }

        i++;
    }

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "ldap_verifier: bye!\n" );

    return(got_error);
}


#else /* ENABLE_LDAP */

static int ldap_v(const char *userid,
		  const char *passwd,
		  const char *service,
		  const char *user_realm,
		  struct credentials **creds,
		  const char **errstr)
{
    if (creds) *creds = NULL;

    *errstr = "ldap not implemented";
    return -1;
}
#endif

verifier ldap_verifier = { "ldap", &ldap_v, NULL, NULL };
