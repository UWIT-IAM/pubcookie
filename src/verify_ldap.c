/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file verify_ldap.c
 * LDAP Verifier
 *
 * Verifies users against an LDAP server (or servers.)
 * 
 * $Id: verify_ldap.c,v 1.25 2004-12-22 22:14:54 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */


/* a pointer for an Apache memory pool is passed everywhwere */
typedef void pool;

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
#include "pbc_configure.h"
#include "snprintf.h"

/* Error logging! */
#include "pbc_logging.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/**
 * Generates the name for the config file key
 * @param prefix char *
 * @param suffix char *
 * @retval malloc()d string (must be free()d!)
 */
static char *gen_key (const char *prefix, char *suffix)
{
    char *result;
    size_t len;
    int num;

    if (prefix == NULL)
        prefix = "";

    if (suffix == NULL)
        suffix = "";

    /* Add 2, one for the \0 and one for a _ */
    len = strlen (prefix) + strlen (suffix) + 7;

    result = calloc (len, sizeof (char));

    num = snprintf (result, len, "ldap%s%s_%s",
                    strlen (prefix) ? "_" : "", prefix, suffix);

    if (num >= len)
        return NULL;

    return result;

}

/**
 * Actually does an LDAP Bind
 * @param p pool *
 * @param ld LDAP *
 * @param user char *
 * @param password char *
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int do_bind (pool * p, LDAP * ld, char *user,
                    const char *password, const char **errstr)
{
    int rc;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "do_bind: hello\n");

    rc = ldap_simple_bind_s (ld, user, password);

    if (rc != LDAP_SUCCESS) {
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "do_bind: failed - %s\n",
                          ldap_err2string (rc));
        *errstr = "Bind failed -- auth failed";
        return -1;
    } else {
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "do_bind: bind successful\n");
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "do_bind: bye!\n");

    return 0;
}

#ifdef LDAP_SUN

void urlcpy (char *dest, char *src, int len)
{
    if (strchr (src, '%') == NULL) {
        strlcpy (dest, src, len);
    } else {
        int i = 0;
        int j = 0;

        /* I know, it's sloppy to just fail to char-by-char, but I'm lazy. */

        for (i = 0; i < len && src[i] != '\0'; i++) {
            if (src[i] != '%') {
                dest[j] = src[i];
            } else {
                int num = 0;
                int old;

                old = src[i + 3];
                src[i + 3] = '\0';

                num = (int) strtol (&src[i + 1], NULL, 16);

                dest[j] = num;

                src[i + 3] = old;

                i += 2;
            }

            j++;
        }
        dest[j] = '\0';
    }
}

char **parse_url_exts (char *ldap_url)
{
    char *p = ldap_url;
    char *q = NULL;
    int i;
    char **retval = NULL;
    int retnum = 0;
    int len;

    /* Skip the first four '?' to get to the extended data. */
    for (i = 0; i < 4; i++) {
        p = strchr (p, '?');
        if (p == NULL)
            return NULL;
        p++;
    }

    /* p should point to the '?' beginning the extended data */

    if (*p == '?' && *(p - 1) != '?') {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "Error parsing \"%s\": p=\"%s\"", ldap_url, p);
        return NULL;
    }

    if (*p == '\0') {
        pbc_log_activity (p, PBC_LOG_ERROR, "No Extended data on \"%s\"",
                          ldap_url);
        return NULL;
    }

    while (p != NULL) {

        retnum++;

        q = strchr (p, ',');

        if (q != NULL)
            *q = '\0';

        if (retval == NULL)
            retval = malloc (sizeof (char *) * retnum);
        else
            retval = realloc (retval, sizeof (char *) * retnum);

        len = strlen (p) + 1;

        retval[retnum - 1] = malloc (sizeof (char) * len);

        urlcpy (retval[retnum - 1], p, len);

        if (q != NULL) {
            *q = ',';
            p = q + 1;
        } else
            p = NULL;

        q = NULL;

    }

    if (retval != NULL) {
        retval = realloc (retval, sizeof (char *) * retnum + 1);
        retval[retnum] = NULL;
    }

    return retval;
}

#endif

/**
 * Connects to an LDAP Server
 * @param p poll *
 * @param ld LDAP **
 * @param ldap_port int
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int ldap_connect (pool * p, LDAP ** ld,
                         char *ldap_uri, const char **errstr)
{
    int rc = 0;
    char *tmp_uri;
    int tmplen = 0;

    char *dn = NULL;
    char *pwd = NULL;

    LDAPURLDesc *ludp;
    char **exts = NULL;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "ldap_connect: hello\n");

    if (ldap_url_parse (ldap_uri, &ludp)) {
        pbc_log_activity (p, PBC_LOG_ERROR, "Cannot parse \"%s\"\n",
                          ldap_uri);
        *errstr = "System Error.  Contact your system administrator.";
        return -1;
    }

    if ((exts =
#ifdef LDAP_OPENLDAP
         ludp->lud_exts
#else
# ifdef LDAP_SUN
         parse_url_exts (ldap_uri)
# else
#  error "No LDAP API!"
# endif /* LDAP_SUN */
#endif /* LDAP_OPENLDAP */
        ) != NULL) {

        while (*exts != NULL) {
            char *val = strchr (*exts, '=');

            if (val != NULL) {

                *val = '\0';
                val++;

                if (strcasecmp (*exts, "x-BindDN") == 0) {
                    dn = strdup (val);
                } else if (strcasecmp (*exts, "x-Password") == 0) {
                    pwd = strdup (val);
                } else {
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "ldap_connect: unknown extension %s=%s\n",
                                      *exts, val);
                }
            } else {
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "ldap_connect: extension error parsing \"%s\"\n",
                                  *exts);
            }

            exts++;
        }
    }
#ifdef LDAP_OPENLDAP

    /*
     * Work around a bug in the OpenLDAP stuff that causes the init to fail when
     * there are things other than the server name in the URI.
     */

    /* The magic number 6 here is the most number of digits a port number can
     * have, i.e. 65535, plus one for the \0. */

    tmplen = strlen (ludp->lud_scheme) + strlen (ludp->lud_host) + 6 +
        strlen ("://:/");

    tmp_uri = malloc (tmplen);

    snprintf (tmp_uri, tmplen, "%s://%s:%d/",
              ludp->lud_scheme, ludp->lud_host, ludp->lud_port);

    /* lookup DN for username using an anonymous bind */
    rc = ldap_initialize (ld, tmp_uri);

    free (tmp_uri);
#else
# ifdef LDAP_SUN
    if (exts != NULL)
        free (exts);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "Server: %s Port: %d SSL: %d", ludp->lud_host,
                      ludp->lud_port,
                      ludp->lud_options & LDAP_URL_OPT_SECURE);

    if (ludp->lud_options & LDAP_URL_OPT_SECURE) {

        if (ldapssl_client_init (CERT_DB_PATH, NULL) != 0) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "Error loading cert db \"%s\"!",
                              CERT_DB_PATH);
            return -2;
        }

        *ld = (LDAP *) ldapssl_init (ludp->lud_host, ludp->lud_port, 1);
    } else {
        *ld = ldap_init (ludp->lud_host, ludp->lud_port);
    }

    if (*ld == (LDAP *) - 1)
        *ld = NULL;

    if (*ld != NULL) {
        int three = LDAP_VERSION3;

        rc = ldap_set_option (*ld, LDAP_OPT_PROTOCOL_VERSION, &three);
    }
# endif /* LDAP_SUN */
#endif /* LDAP_OPENLDAP */

    if (rc != LDAP_SUCCESS || *ld == NULL) {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "ldap_connect: LDAP Initialization error %d.\n",
                          rc);
        *errstr = "connection to ldap server failed -- auth failed";
        return -2;
    }

    rc = do_bind (p, *ld, dn, pwd, errstr);

    /* OK, We're bound, so we don't need the dn/pwd strings anymore.. */

    if (dn != NULL)
        free (dn);

    if (pwd != NULL)
        free (pwd);

    if (rc == -1) {
        /* Here a bind failing isn't catastrophic..  */
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "ldap_connect: Bind Failed.\n");
        /* ldap_unbind(*ld); */
        return -2;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "ldap_connect: bye!\n");

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
static int get_dn (pool * p, LDAP * ld,
                   char *ldapuri, char **dn, const char **errstr)
{
    int err = 0;
    int num_entries;


    LDAPMessage *results = NULL;
    LDAPMessage *entry = NULL;
    LDAPURLDesc *ludp = NULL;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "get_dn: hello\n");

    *dn = NULL;

    if (ldap_url_parse (ldapuri, &ludp)) {
        pbc_log_activity (p, PBC_LOG_ERROR, "Cannot parse \"%s\"\n",
                          ldapuri);
        *errstr = "System Error.  Contact your system administrator.";
        return -1;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "searching: %s for %s",
                      ludp->lud_dn, ludp->lud_filter);

    err = ldap_search_s (ld, ludp->lud_dn, LDAP_SCOPE_SUBTREE,
                         ludp->lud_filter, NULL, 0, &results);

    if (err != LDAP_SUCCESS) {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "User not found - error %d (%s)!",
                          err, ldap_err2string (err));
        *errstr = "user not found -- auth failed";
        return -1;
    }

    num_entries = ldap_count_entries (ld, results);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "get_dn: Found %d Entries\n", num_entries);

    if (num_entries != 1) {
        ldap_msgfree (results);
        *errstr = "too many or no entries found -- auth failed";
        return -1;
    }

    entry = ldap_first_entry (ld, results);

    if (entry == NULL) {
        ldap_msgfree (results);
        *errstr = "error getting ldap entry -- auth failed";
        /* The server had something go wrong -- OK to try again. */
        return -2;
    }

    *dn = ldap_get_dn (ld, entry);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "get_dn: Got DN: \"%s\"\n",
                      *dn);

    if (*dn == NULL) {
        ldap_msgfree (results);
#ifdef LDAP_SUN
        ldap_msgfree (entry);
#endif
        *errstr = "error getting ldap dn -- auth failed";
        /* Again not fatal, probably a server error. */
        return -2;
    }

    ldap_msgfree (results);
#ifdef LDAP_SUN
    ldap_msgfree (entry);
#endif

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "get_dn: bye!\n");

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

static int ldap_v (pool * p, const char *userid,
                   const char *passwd,
                   const char *service,
                   const char *user_realm,
                   struct credentials **creds, const char **errstr)
{
    int got_error = -2;
    int i = 0;

    char **ldap_uri_list;
    char *key = NULL;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "ldap_verifier: hello\n");

    if (creds)
        *creds = NULL;

    key = gen_key (user_realm, "uri");
    ldap_uri_list = libpbc_config_getlist (p, key);
    free (key);

    if (service != NULL) {
        *errstr = "LDAP Verifier can't handle Service cleanly...";
        return -2;
    }

    if (userid == NULL || strlen (userid) == 0) {
        *errstr = "Username MUST be specified.";
        return -2;
    }

    if (passwd == NULL || strlen (passwd) == 0) {
        *errstr = "Password MUST be specified.";
        return -2;
    }

    while ((got_error == -2)
           && (ldap_uri_list != NULL)
           && (ldap_uri_list[i] != NULL)) {
        char *ldap_uri_in = ldap_uri_list[i];
        char *ldap_uri;
        int len, num;

        LDAP *ld = NULL;
        char *user_dn = NULL;
        char *limit, *ptr_in, *ptr_out;

        if (strstr (ldap_uri_in, "%s") == NULL) {
            /* The LDAP URI must contain a %s to hold the user name! */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        /* Something big enough to hold the uri, userid and a \0 */
        len = strlen (ldap_uri_in) + strlen (userid) + 1;
        ldap_uri = malloc (len);

        if (ldap_uri == NULL) {
            /* Ooops, out of memory! */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        /* Copy the bytes which precede the (first) %s into the allocated URI
         * string. 
         */

        ptr_in = ldap_uri_in;
        ptr_out = ldap_uri;
        limit = strstr (ldap_uri_in, "%s");
        while (ptr_in < limit) {
            *ptr_out++ = *ptr_in++;
        }

        /* Add the userid to the allocated URI string */

        *ptr_out = '\0';
        strcat (ptr_out, userid);

        /* Copy the rest of the URI */
        ptr_in = limit + 2;
        ptr_out += strlen (userid);
        limit = ldap_uri_in + strlen (ldap_uri_in);
        while (ptr_in < limit) {
            *ptr_out++ = *ptr_in++;
        }
        *ptr_out = '\0';

        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "ldap_verifier: uri: \"%s\"\n", ldap_uri);

        if (userid == NULL || passwd == NULL) {
            *errstr = "username or password is null -- auth failed";
            got_error = -1;
        }

        /*
         * The definately needs to be changed.  There will need to be a
         * "searching" login that we use to find the Dn.
         */
        got_error = ldap_connect (p, &ld, ldap_uri, errstr);
        if (got_error == 0) {

            got_error = get_dn (p, ld, ldap_uri, &user_dn, errstr);

            if (got_error == 0 && strlen (user_dn)) {
                LDAPURLDesc *ludp;
                int err;

                if (ldap_url_parse (ldap_uri, &ludp)) {
                    /* For some reason we can't parse the URL. Eeek. */
                    got_error = -2;
                } else {

                    got_error = do_bind (p, ld, user_dn, passwd, errstr);

                    if (got_error != 0)
                        *errstr = "couldn't bind as user -- auth failed";

                    if (got_error == 0) {
                        pbc_log_activity (p, PBC_LOG_AUDIT,
                                          "%s succesfully bound to %s:%d\n",
                                          userid, ludp->lud_host,
                                          ludp->lud_port);
                    } else if (got_error == -1) {
                        pbc_log_activity (p, PBC_LOG_AUDIT,
                                          "%s fatal error binding to %s:%d\n",
                                          userid, ludp->lud_host,
                                          ludp->lud_port);
                    } else if (got_error == -2) {
                        pbc_log_activity (p, PBC_LOG_AUDIT,
                                          "%s error binding to %s:%d.  Continuing\n",
                                          userid, ludp->lud_host,
                                          ludp->lud_port);
                    }
                }

            }

            if (user_dn != NULL)
                free (user_dn);

            /* close ldap connection */
            ldap_unbind (ld);
        }

        if (ldap_uri != NULL)
            free (ldap_uri);

        i++;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "ldap_verifier: bye!\n");

    return (got_error);
}


#else /* ENABLE_LDAP */

static int ldap_v (pool * p, const char *userid,
                   const char *passwd,
                   const char *service,
                   const char *user_realm,
                   struct credentials **creds, const char **errstr)
{
    if (creds)
        *creds = NULL;

    *errstr = "ldap not implemented";
    return -1;
}
#endif

verifier ldap_verifier = { "ldap", &ldap_v, NULL, NULL };
