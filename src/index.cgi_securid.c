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
    $Id: index.cgi_securid.c,v 1.1 2000-08-22 19:30:45 willey Exp $
 */


/* LibC */
#include <stdlib.h>
/* securid */
#include "securid.h"
/* pubcookie things */
#include "index.cgi.h"

/* all of the securid stuff is in files name securid_                         */
char *auth_securid(char *username, char *sid, int next, login_rec *l) 
{
    int		intret;

    /* securid and next prn */
    if( (intret=securid(username, sid,0,SECURID_TYPE_NORM,SECURID_DO_SID) == -1) ) {
         print_login_page(l, "Next SecurID PRN", "next PRN", NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
    } 
    else if( intret == 0 ) {
        return(NULL);
    }

    return("SecurID failed");

}
