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

    the shadow_verifier verifies a username and password 
    against /etc/shadow.  sadly, it must be able to read
    /etc/shadow.  

 */

/*
    $Id: verify_shadow.c,v 1.9 2003-03-06 06:12:50 jjminer Exp $
 */

/**
 *
 *  @return 0 on success, -1 if user/pass doesn't match, -2 on system error
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
# ifndef APACHE
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

    struct spwd * shadow;
    char * crypted;

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

    setspent();
    shadow = getspnam(userid);
    endspent();

    if (shadow == NULL) {
       *errstr = "unable to get entry from /etc/shadow";
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
