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
    $Id: index.cgi_securid.c,v 1.3 2000-09-25 17:58:31 willey Exp $
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
char *auth_securid(char *user, char *sid, int next, login_rec *l) 
{
    int		intret;
    char	*reason = NULL;
    char        *card_id;
    char        *prn = NULL;
    char        *p;

    /* if the securid field is really in the form card_id=prn seperate it */
    card_id = malloc((strlen(sid)>strlen(user) ? strlen(sid) : strlen(user))+1);
    p = card_id = sid;
    while( *p ) {
      if( *p == '=' ) {
          *p = '\0';
          prn = ++p;
      } 
      p++;
    }
    if( prn == NULL ) {
        card_id = user;
        prn = sid;
    }

    /* take back being root */
    if( setreuid(65534, 0) != 0 )
        log_message("%s auth_securid: unable to setuid root", l->first_kiss);

//#ifdef DEBUG
    log_message("%s auth_securid: about to securid check user: %s card_id: %s prn: %s ", l->first_kiss, user, card_id, prn);
//#endif

    /* securid and next prn */
    intret = securid(reason, user, card_id, prn, 1, SECURID_TYPE_NORM, SECURID_DO_SID);

//#ifdef DEBUG
    log_message("auth_securid: message from securid %s", reason);
//#endif

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
