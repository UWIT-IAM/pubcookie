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

    this is simply a header file with the version in it.  do you like that 
       there are more lines of comment then code?

 */

/*
    $Id: pbc_login_cgi.h,v 1.1 2000-01-27 22:16:06 willey Exp $
 */

#ifndef PUBCOOKIE_CGI
#define PUBCOOKIE_CGI

#endif /* !PUBCOOKIE_CGI */

#include "pbc_config.h"
#include "pbc_version.h"
#include "pubcookie.h"

/* some setting for the cookies and redirect */
#define LOGIN_DIR "/"
#define REFRESH "0"
#define EXPIRE_LOGIN 60 * 60 * 8

/* some messages about people who hit POSTS and don't have js on */
#define PBC_POST_NO_JS_TEXT "Thank you for logging on\n"
#define PBC_POST_NO_JS_BUTTON "Click here to continue\n"

#define PRINT_LOGIN_PLEASE "Please log in."
#define TROUBLE_CREATING_COOKIE "Trouble creating cookie, please re-enter."
#define PROBLEMS_PERSIST "If problems persist contact help\@cac.washington.edu."
#define AUTH_FAILED_MESSAGE1 "Login failed. Please re-enter."
#define AUTH_FAILED_MESSAGE2 "Please make sure:<BR><UL><LI>Your Caps Lock key is OFF.<LI>Your Number Lock key is ON.</UL>"

#define PROMPT_UWNETID "<B>Password:</B><BR>\n"
#define PROMPT_SECURID "<B>SecurID:</B><BR>\n"

/* how we accentuate WARNING messages */
#define PBC_EM1_START "<B><font color=\"#FF0000\" size=\"+1\">"; 
#define PBC_EM1_END "</font></B><BR>"
/* how we accentuate less important WARNING messages */
#define PBC_EM2_START "<B><font size=\"+1\">"; 
#define PBC_EM2_END "</font></B><BR>"

/* keys and certs */
#define KEY_DIR "/usr/local/pubcookie/"
#define CRYPT_KEY $key_dir . "c_key." . $host
#define CERT_FILE $key_dir . "pubcookie.cert"
#define CERT_KEY_FILE $key_dir . "pubcookie.key"

/* programs for creating and verifying cookies */
#define CREATE_PGM "/usr/local/pubcookie/pbc_create"
#define VERIFY_PGM "/usr/local/pubcookie/pbc_verify"

/* some misc settings */
#define SERIAL_FILE "/tmp/s"
#define FIRST_SERIAL 23

/* file to get the list of ok browsers from */
#define OK_BROWSERS_FILE "/usr/local/pubcookie/ok_browsers"

/* utility to send messages to pilot */
#define SEND_PILOT_CMD "/usr/local/adm/send_pilot_stat.pl"

