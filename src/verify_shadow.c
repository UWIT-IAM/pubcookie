/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file verify_shadow.c
 * /etc/shadow verifier
 *
 *    the shadow_verifier verifies a username and password 
 *    against /etc/shadow.  sadly, it must be able to read
 *    /etc/shadow.  
 *  
 *    @return 0 on success, -1 if user/pass doesn't match, -2 on system error
 *  
 * $Id: verify_shadow.c,v 1.16 2004-11-22 19:04:42 willey Exp $
 */
 

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

/* Pretending we're Apache */
typedef void pool;

#include "verify.h"

#ifdef ENABLE_SHADOW

#ifdef HAVE_SHADOW_H
# include <shadow.h>
#endif /* HAVE_SHADOW_H */

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif /* HAVE_CRYPT_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

static int shadow_v(pool * p, const char *userid,
		    const char *passwd,
		    const char *service,
		    const char *user_realm,
		    struct credentials **creds,
		    const char **errstr)
{

    struct spwd *shadow;
    char *crypted;
    FILE *pwfile;

    if (errstr) *errstr = NULL;
    if (creds) *creds = NULL;

    if (!userid) {
       *errstr = "no userid to verify";
       return -1;
    }

    if (!passwd) {
       *errstr = "no password to verify";
       return -1;
    }


    pwfile = fopen(SHADOW_PATH, "r");
    setspent();
    while (shadow = fgetspent(pwfile))
       if (strcmp(userid, shadow->sp_namp) == 0)
           break;
    endspent();

    fclose(pwfile);

    if (shadow == NULL) {
       *errstr = "unable to get entry from shadow file";
       return -2;
    }

    crypted = crypt(passwd, shadow->sp_pwdp);

    if (crypted == NULL) {
       *errstr = "error crypt'ing passwd";
       return -2;
    }

    if (strcmp(shadow->sp_pwdp, crypted) == 0) {
       return 0;
    }
    
    *errstr=("username/password pair is incorrect");
    return -1;
}

#else /* ENABLE_SHADOW */

static int shadow_v(pool * p, const char *userid,
		    const char *passwd,
		    const char *service,
		    const char *user_realm,
		    struct credentials **creds,
		    const char **errstr)
{
    if (creds) *creds = NULL;

    *errstr = "shadow verifier not implemented";
    return -1;
}

#endif /* ENABLE_SHADOW */

verifier shadow_verifier = { "shadow", &shadow_v, NULL, NULL };
