/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is the securid auth portion of the pubcookie login cgi.

 */

/*
    $Id: index.cgi_etcpasswd.c,v 1.3 2002-03-05 21:41:00 willey Exp $
 */


/* LibC */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
/* pubcookie things */
#include "index.cgi.h"

char *auth_etcpasswd(char *user, char *passwd, login_rec *l) 
{
    const char		*pwfile = "/etc/passwd"; 
    struct passwd	*passwd;
    char		*crypted;
    FILE		*ifp;

#ifdef DEBUG
    log_message("%s auth_etcpasswd: gonna look for: %s", l->first_kiss, user);
#endif

    if( !(ifp = pbc_fopen(pwfile, "r")) )
        return("cannot open the password file for read\n");

    pwd = getpwnam(user);
    crypted = pwd->pw_password;

    return(check_password(password, crypted));

}


char *check_password(const char *passwd, const char *hash)
{
    char sample[120];

    strncpy(sample, (char *)crypt(passwd, hash), sizeof(sample) - 1);

    return (strcmp(sample, hash) == 0) ? NULL : "password mismatch";

}

