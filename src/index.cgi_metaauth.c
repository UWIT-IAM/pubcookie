/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: https:/www.washington.edu/pubcookie/
    Written by the Pubcookie Team

    this is the meta-auth portion of the pubcookie login cgi.

 */

/*
    $Id: index.cgi_metaauth.c,v 1.1 2000-08-22 19:30:45 willey Exp $
 */


/* LibC */
#include <stdlib.h>
#include <string.h>
/* pubcookie things */
#include "index.cgi.h"
/* meta-auth */
#include <authsrv.h>


const char *mkcred (const char *key, const char *val) {
    char        *dest = (char *)malloc(strlen(key) + strlen(val) + 2);

    strcpy (dest, key);
    strcat (dest, "=");
    strcat (dest, val);

    return dest;
}

/* returns NULL for ok and a message for failure                              */
char *auth_ndcpasswd(const char *user, const char *pass)
{
    int		success = 0;
    char	*result = NULL;
    int		resultlen = 0;
    int		timeout = 20;
    const char	*sessid = NULL;
    short 	flags = REQFL_AUTH_ONLY;
    FOURBYTEINT	hard_timeout = 1;
    FOURBYTEINT	int_timeout = 0;
    const char	*creds[3] = { 0, 0, 0 };
    const char	*authtypes[] = {
        "ndcpasswd",
        0
    };

    /* make creds array for meta-auth*/
    creds[0] = mkcred(NDCUSERNAME, user);
    creds[1] = mkcred(NDCPASSWORD, pass);

    success = authsrv_authenticate ( result, resultlen, timeout, sessid, flags, hard_timeout, int_timeout, authtypes, creds);

#ifdef DEBUG
            fprintf(stderr, "auth_ndcpasswd: success is %d result is %s\n", success, result);
#endif

    if( success ) 
        return(NULL);
    else
        if( !result ) 
            return("NDCpasswd Fail");
        else
            return(result);

}

