/*

    Copyright 1999-2002, University of Washington.  All rights reserved.
    see doc/LICENSE.txt for copyright information

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|

    All comments and suggestions to pubcookie@cac.washington.edu
    More information: http://www.pubcookie.org/
    Written by the Pubcookie Team

    verifier interface

 */

/*
    $Id: verify.h,v 1.6 2002-08-20 20:31:18 greenfld Exp $
 */
#ifndef INCLUDED_VERIFY_H
#define INCLUDED_VERIFY_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/*
  VERIFIERS

  a verifier is the backend of the login cgi.  it checks a
  username/password combination and returns a YES or a NO.

  some verifiers may also support credentials.  the credentials
  returned with a YES answer represent the "master" credentials for
  this user, good for the rest of the login-cookie session.

  the login server may save the master credentials (by encoding 'str'
  into a cookie with suitable protection) and later derive delegatable
  credentials from them using credentials_derive() for that verifier.
*/


/* serialized version of credentials */
struct credentials {
    int sz;
    char *str;
};

/**
 * verify a plaintext password
 * @param userid the userid as entered by the user to the web form
 * @param passwd the password as entered by the user to the web form
 * @param service the requested service (currently unused)
 * @param user_realm the realm selected from the drop-down list, if
 *        the calling flavor is configured for multiple realms
 * @param creds if the flavor is configured to store credentials
 *        for deriving future proxy credentials, this parameter should
 *        be non-NULL.  it will be filled in by a credential structure
 *        which should be later free'd with credentials_free()
 * @param errstr a user visible error string.  it is statically
 *        allocated and should not be free'd.
 * @returns 0 on success. any non-zero response should be considered
 *         failure. specifically: -1 indicates a try-again failure, 
 *         -2 indicates a system error
*/
/* returns 0 on success; non-zero on failure */
typedef int plaintext_verifier(const char *userid,
			       const char *passwd,
			       const char *service,
			       const char *user_realm,
			       struct credentials **creds,
			       const char **errstr);

/**
 * free credentials returned from plaintext_verifier() or credentials_derive()
 * @param creds the credentials to free
 * @returns always succeeds
 */
typedef void credentials_free(struct credentials *creds);


/**
 * returns new credentials for use by 'app' to authenticate by
 * 'target', asserting the same identity as 'creds'
 * @param creds credentials returned from plaintext_verifier() or
 *        retrieved from a cached, serialized copy
 * @param app the name of the requesting application
 * @param target the name of the target application (ie, a backend
 *        IMAP server)
 * @param newcreds returns the new credentials to be passed to 'app',
 *        which must later be free'd with credentials_free()
 * @returns 0 on success, non-zero on failure
 */
typedef int credentials_derive(struct credentials *creds,
			       const char *app,
			       const char *target,
			       struct credentials **newcreds);

typedef struct verifier_s {
    const char *name;
    plaintext_verifier *v;
    credentials_free *cred_free;
    credentials_derive *cred_derive;
} verifier;

/* given a string, find the corresponding verifier */
verifier *get_verifier(const char *name);

#endif
