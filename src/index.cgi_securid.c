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

    this is the securid auth portion of the pubcookie login cgi.

 */

/*
    $Id: index.cgi_securid.c,v 1.2 2000-09-08 19:20:24 willey Exp $
 */


/* LibC */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
/* securid */
#include "securid.h"
/* pubcookie things */
#include "index.cgi.h"

/* all of the securid stuff is in files name securid_                         */
char *auth_securid(char *username, char *sid, int next, login_rec *l) 
{
    int		intret;
    char	*reason;

    /* take back being root */
    if( setreuid(65534, 0) != 0 )
        log_message("%s auth_securid: unable to setuid root", l->first_kiss);

    /* securid and next prn */
    intret = securid(reason,username,sid,1,SECURID_TYPE_NORM,SECURID_DO_SID);

#ifdef DEBUG
    log_message("auth_securid: message from securid %s", reason);
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
