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
    $Id: index.cgi_etcpasswd.c,v 1.2 2001-12-09 09:12:22 willey Exp $
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
#ifdef SHADOW 
    const char		*shadow = "/etc/shadow";
    struct spwd 	*spwd;
#else
    const char		*pwfile = "/etc/passwd"; 
    struct passwd	*passwd;
#endif
    char		*crypted;

#ifdef DEBUG
    log_message("%s auth_etcpasswd: gonna look for: %s", l->first_kiss, user);
#endif


#ifdef SHADOW 
    spwd = getspnam(user);
    crypted = spwd->sp_pwdp;
#else
    pwd = getpwnam(user);
    crypted = pwd->pw_password;
#endif

    /* give it up permanently */
    if( setreuid(65534, 65534) != 0 )
        log_message("%s auth_securid: unable to setuid nobody", l->first_kiss);

    if( intret == -1 ) {
         print_login_page(l, "Next SecurID PRN", "next PRN", NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
    } 
    else if( intret == 0 ) {       /* O.K. !!!!!!!! */
        return(NULL);
    }

    return("SecurID failed");

}
