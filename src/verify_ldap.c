/** @file verify_ldap.c
 * LDAP Verifier
 *
 * Verifies users against an LDAP server (or servers.)
 * 
 * $Id: verify_ldap.c,v 1.8 2002-07-05 23:35:48 jjminer Exp $
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

/** The debug level */
extern int debug;

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
    len =  strlen(prefix) + strlen(suffix) + 2;

    result = calloc( len, sizeof(char) );

    num = snprintf( result, len, "%s_%s", prefix, suffix );

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

    if (debug)
        fprintf( stderr, "do_bind: hello\n" );

    rc = ldap_simple_bind_s (ld, user, password );

    if ( rc != LDAP_SUCCESS) {
        if (debug) {
            fprintf(stderr, "do_bind: failed - %s\n", ldap_err2string(rc));
        }
        *errstr  = "Bind failed -- auth failed";
        return -1;
    } else if ( debug ) {
            fprintf( stderr, "do_bind: bind successful\n");
    }

    if (debug) {
        fprintf( stderr, "do_bind: bye!\n" );
    }

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
			 char * ldap_server, 
			 int ldap_port, 
			 char * dn, 
			 char * pwd,
			 const char ** errstr ) 
{
    int rc;

    if (debug) {
        fprintf( stderr, "ldap_connect: hello\n" );
    }

    /* lookup DN for username using an anonymous bind */
    *ld = ldap_init(ldap_server, ldap_port);
    if (ld == NULL) {
        if (debug)
            fprintf(stderr, "ldap_connect: LDAP Initialization error!\n");
        *errstr = "connection to ldap server failed -- auth failed";
        return -2;
    }

    rc = do_bind( *ld, dn, pwd, errstr );

    if( rc == -1 ) {
        /* Here a bind failing isn't catastrophic..  */
        if (debug)
            fprintf( stderr, "ldap_connect: Bind Failed.\n" );
        ldap_unbind(*ld);
        return -2;
    }

    if (debug) {
        fprintf( stderr, "ldap_connect: bye!\n" );
    }

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
		   char * searchbase, 
		   char * attr, 
		   const char * val, 
		   char ** dn,
		   const char ** errstr )
{
    char * ldap_filter;

    int len;
    int num;
    int err;
    int num_entries;

    LDAPMessage * results, * entry;

    if( debug ) {
        fprintf( stderr, "get_dn: hello\n" );
    }

    *dn = NULL;

    if( attr == NULL || val == NULL || strlen(attr) == 0 || strlen(val) == 0 ) {
        fprintf( stderr, "Error - attr: \"%s\" val: \"%s\"", 
                 attr == NULL ? "(null)" : attr, val == NULL ? "(null)" : val );
        return -2;
    }

    len = strlen(attr) + strlen(val) + strlen("(=)") + 1;

    ldap_filter = calloc( len, sizeof(char) );

    if ( ldap_filter == NULL ) {
        return -1;
    }

    num = snprintf( ldap_filter, len, "(%s=%s)", attr, val );

    if ( num >= len ) {
        return -1;
    }

    if (debug) {
        fprintf( stderr, "get_dn: Created filter: %s\n", ldap_filter );
    }

    err = ldap_search_s( ld, searchbase, LDAP_SCOPE_SUBTREE,
                         ldap_filter, NULL, 0, &results );

    if (err != LDAP_SUCCESS) {
        *errstr = "user not found -- auth failed";
        return -1;
    }

    free(ldap_filter);

    num_entries = ldap_count_entries(ld, results);

    if (debug) {
        fprintf( stderr, "get_dn: Found %d Entries\n", num_entries );
    }

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

    if (debug) {
        fprintf( stderr, "get_dn: Got DN: \"%s\"\n", *dn );
    }
    
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

    if( debug ) {
        fprintf( stderr, "get_dn: bye!\n" );
    }

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

    char  **ldap_server_list;
    char  **ldap_port_list;
    char  **ldap_search_base_list;
    char  **ldap_uid_attribute_list;
    char *key = NULL;

    if ( debug ) {
        fprintf( stderr, "ldap_verifier: hello\n" );
    }

    if (creds) *creds = NULL;

    /* What should we do when the realm is null? I'm defaulting to "ldap" */

    if( user_realm == NULL ) {
        user_realm = "ldap";
    }

    key = gen_key(user_realm, "server");
    ldap_server_list = libpbc_config_getlist(key);
    free(key);

    key = gen_key(user_realm, "port");
    ldap_port_list = libpbc_config_getlist( key );
    free(key);

    key = gen_key(user_realm, "searchbase");
    ldap_search_base_list = libpbc_config_getlist( key );
    free(key);

    key = gen_key(user_realm, "uid");
    ldap_uid_attribute_list = libpbc_config_getlist( key );
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
            && (ldap_server_list != NULL)
            && (ldap_server_list[i] != NULL) ) {

        char *ldap_server = ldap_server_list[i];
        char *ldap_search_base = ldap_search_base_list[i];
        char *ldap_uid_attribute = ldap_uid_attribute_list[i];
        char *ldap_port_str = ldap_port_list[i];
        LDAP *ld = NULL;
        char  *user_dn = NULL;
        int ldap_port;

        if( ldap_port_str == NULL )
            ldap_port = LDAP_PORT;
        else
            ldap_port = atoi( ldap_port_str );

        if (debug) {
            fprintf( stderr, "ldap_verifier: server: %s port: %d\n",
                     ldap_server, ldap_port );
            fprintf( stderr, "ldap_verifier: search base: %s uid: %s\n",
                     ldap_search_base, ldap_uid_attribute );
        }

        if (userid == NULL || passwd == NULL) {
            *errstr = "username or password is null -- auth failed";
            got_error = -1;
        }

        /*
         * The definately needs to be changed.  There will need to be a
         * "searching" login that we use to find the Dn.
         */
        got_error = ldap_connect( &ld, ldap_server, ldap_port, NULL, NULL, errstr );
        if( got_error == 0 ) {

            got_error = get_dn( ld, ldap_search_base, ldap_uid_attribute, userid,
                                &user_dn, errstr );

            if( got_error == 0 ) {

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

    if( ldap_search_base_list != NULL ) {
        free(ldap_search_base_list);
    }
    if( ldap_server_list != NULL ) {
        free(ldap_server_list);
    }
    if( ldap_uid_attribute_list != NULL ) {
        free(ldap_uid_attribute_list);
    }
    if( ldap_port_list != NULL ) {
        free(ldap_port_list);
    }

    if( debug ) {
        fprintf( stderr, "ldap_verifier: bye!\n" );
        fprintf( stderr, "returning: %d\n", got_error );
    }

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
