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

    this is the header file for index.cgi the pubcookie login cgi

 */

/*
    $Id: index.cgi.h,v 1.1 1999-10-15 23:42:36 willey Exp $
 */


#define LOGIN_DIR "/"
#define REFRESH "0"
#define EXPIRE_LOGIN 60 * 60 * 8

#define NOTOK_NEEDSSL "I'm sorry this page is only accessible via a ssl protected connection.<BR>\n"

/* some messages about people who hit posts and don't have js on */
#define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"
#define PBC_POST_NO_JS_BUTTON "Click here to continue\n"

#define PRINT_LOGIN_PLEASE "Please log in."
#define TROUBLE_CREATING_COOKIE "Trouble creating cookie.  Please re-enter."
#define PROBLEMS_PERSIST "If problems persist contact help\@cac.washington.edu."
#define AUTH_FAILED_MESSAGE1 "Login failed.  Please re-enter."
#define AUTH_FAILED_MESSAGE2 "Please make sure:<BR><UL><LI>Your caps lock key is off.<LI>Your number lock key is on.</UL>"

#define PROMPT_UWNETID "<B>Password:</B><BR>\n"
#define PROMPT_SECURID "<B>Securid:</B><BR>\n"

/* how we accentuate warning messages */
#define PBC_EM1_START "<B><FONT COLOR=\"#FF0000\" SIZE=\"+1\">"; 
#define PBC_EM1_END "</FONT></B><BR>"
/* how we accentuate less important warning messages */
#define PBC_EM2_START "<B><FONT SIZE=\"+1\">"; 
#define PBC_EM2_END "</FONT></B><BR>"

/* keys and certs */
#define KEY_DIR "/usr/local/pubcookie/"
#define CRYPT_KEY "c_key"
#define CERT_FILE "pubcookie.cert"
#define CERT_KEY_FILE "pubcookie.key"

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

