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

    this is the header file for index.cgi the pubcookie login cgi

 */

/*
 * $Revision: 1.32 $
 */

#ifndef PUBCOOKIE_LOGIN_CGI
#define PUBCOOKIE_LOGIN_CGI

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* cgic---needed for typenames */
#ifdef HAVE_CGIC_H
# include <cgic.h>
#endif /* HAVE_CGIC_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

typedef struct {
    char	*args;
    char	*uri;
    char	*host;
    char	*method;
    char	*version;
    char	creds;
    char	creds_from_greq;
    char	ride_free_creds;
    char	*appid;
    char	*appsrvid;
    char	*fr;
    char	*user;
    char	*realm;
    char	*pass;
    char	*pass2;
    char	*post_stuff;
    char	*real_hostname;
    char	*appsrv_err;
    char	*appsrv_err_string;
    char	*file;
    char	*flag;
    char	*referer;
    char	type;
    time_t	create_ts;
    time_t	expire_ts;
    int		serial;
    int		next_securid;
    int		session_reauth;
    int		duration;
    char	*first_kiss;
    int		reply;
    int		alterable_username;
    int		pinit;
    int		pre_sess_tok;   
    char        *check_error;
    void *flavor_extension; /* used for ad-hoc purposes until
			       we add a general extension mechanism to the
			       cookie structure */
} login_rec;

struct browser {
    char		agent[1024];
    int			timeout;
    int			allow;
    int			deny;
    struct browser	*next;
    struct browser 	*prev;
};

typedef struct browser browser_rec;

#define FREE_RIDE_MESSAGE "You entered it less than 10 minutes ago.<BR>\n"

/* prototypes */
int cgiMain();
void abend(char *);
int cookie_test();
void notok( void (*)() );
void notok_no_g_or_l();
void print_http_header();
void print_j_test();
void notok_need_ssl();
void notok_no_g();
void notok_formmultipart();
void notok_generic();
void notok_bad_agent();
void print_login_page_part1(char *);
void print_login_page_part5();
int check_user_agent();
void log_message(const char *, ...);
void log_error(int, const char *, int, const char *, ...);
void clear_error(const char *, const char *);
void print_uwnetid_logo();
login_rec *verify_unload_login_cookie (login_rec *);
int create_cookie(char *, char *, char *, char, char, int, time_t, char *, 
		  const char *peer, int);
login_rec *get_query();
char *check_login(login_rec *, login_rec *);
char *check_l_cookie(login_rec *, login_rec *);
void print_redirect_page(login_rec *, login_rec *);
int get_next_serial();
char *url_encode();
char *get_cookie_created(char *);
char *decode_granting_request(char *, char **peerp);
const char *login_host();
const char *enterprise_domain();
int set_pinit_cookie();
int clear_pinit_cookie();
char *get_string_arg(char *name, cgiFormResultType (*f)());

/* print part of the HTML */
void print_html(const char *format, ...);
/* print it from the template "fname" */
void tmpl_print_html(const char *fname,...);

/* print part of the HTTP headers */
void print_header(const char *format, ...);

#define RIDE_FREE_TIME (10 * 60)
#define LOGIN_DIR "/"
#define THIS_CGI "cindex.cgi"
#define REFRESH "0"
#define DEFAULT_LOGIN_EXPIRE (8 * 60 * 60)
#define APP_LOGOUT_STR "app_logout_string"
#define APP_LOGOUT_STR_SEP '-'

#define TMPL_FNAME PBC_PATH "login_templates/"

/* why print login page ? */
#define LOGIN_REASON_AUTH_FAIL   "bad auth"
#define LOGIN_REASON_SECURID     "securid requires reauth"
#define LOGIN_REASON_NO_L        "no L cookie yet"
#define LOGIN_REASON_SESS_REAUTH "session timeout requires reauth"

/* the pinit cookie is used to transition from a pinit login to 
   a pinit responce */
#define PBC_PINIT_COOKIENAME "pinit"

/* some messages about people who hit posts and don't have js on */
#define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"

#define PRINT_LOGIN_PLEASE "Please log in."
#define PRINT_LOGIN_PINIT "Welcome to the UW NetID \"weblogin\" service. Please log in to identify yourself."
#define TROUBLE_CREATING_COOKIE "Trouble creating cookie.  Please re-enter."
#define PROBLEMS_PERSIST "If problems persist contact help@cac.washington.edu."
#define AUTH_FAILED_MESSAGE1 "Login failed.  Please re-enter.\n"
#define AUTH_FAILED_MESSAGE2 "<p>Please make sure your <b>Caps Lock key is OFF</b> and your <b> Number Lock key is ON</b>.</p>"
#define AUTH_TROUBLE "There are currently problems with authentication services, please try again later"

#define CHECK_LOGIN_RET_BAD_CREDS "invalid creds"
#define CHECK_LOGIN_RET_SUCCESS "success"
#define CHECK_LOGIN_RET_FAIL "fail"

/* special strings about time remaining */
#define REMAINING_EXPIRED "expired"
#define REMAINING_UNKNOWN "unknown"

#define PROMPT_UWNETID "<B>UW NetID:</B><BR>"
#define PROMPT_PASSWD "<B>Password:</B><BR>"
#define PROMPT_SECURID "<B>Securid:</B><BR>"
#define PROMPT_INVALID "<B>BOGUS:</B><BR>"

/* tags the request as a reply from the form */
#define FORM_REPLY 1

/* replacement string for g req cookies once they hav gone thru the cgi */
#define G_REQ_RECEIVED "g req received"

/* how we accentuate warning messages */
#define PBC_EM1_START "<P><B><FONT COLOR=\"#FF0000\" SIZE=\"+1\">" 
#define PBC_EM1_END "</FONT></B><BR></P>"
/* how we accentuate less important warning messages */
#define PBC_EM2_START "<P><B><FONT SIZE=\"+1\">" 
#define PBC_EM2_END "</FONT></B><BR></P>"

/* identify log messages */
#define ANY_LOGINSRV_MESSAGE "PUBCOOKIE_LOGINSRV_LOG"
#define SYSERR_LOGINSRV_MESSAGE "PUBCOOKIE SYSTEM ERROR"

/* flags to send to get_string_arg */
#define YES_NEWLINES_FUNC cgiFormString
#define NO_NEWLINES_FUNC cgiFormStringNoNewlines

/* flags to send to print_login_page */
#define YES_CLEAR_LOGIN 1
#define NO_CLEAR_LOGIN 0
#define YES_CLEAR_GREQ 1
#define NO_CLEAR_GREQ 0

/* flags to send to print_login_page_part1 */
#define YES_FOCUS 1
#define NO_FOCUS 0

/* some misc settings */
#define SERIAL_FILE "/tmp/s"
#define FIRST_SERIAL 23

/* file to get the list of ok browsers from */
#define OK_BROWSERS_FILE PBC_PATH "ok_browsers"

/* file to get browser information from */
#define BROWSERS_FILE PBC_PATH "browsers"

#define PBC_BRWSER_OK 0
#define PBC_BRWSER_DENY 1
#define PBC_BRWSER_TO 2

/* utility to send messages to pilot */
#define SEND_PILOT_CMD "/usr/local/adm/send_pilot_stat.pl"


/* text */

#define NOTOK_NO_G_OR_L_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">\
A problem has been detected!</font></B></P> \
\
<p><b><font size=\"+1\">Either your browser is not configured to accept \
cookies,\
or the URL address you opened contains a shortened domain name.</font></b></p>\
\
<p>Review \
<A HREF=\"http://www.washington.edu/computing/web/login-problems.html\">Common\
Problems With the UW NetID Login Page</A> for further advice.</p>\
\
<p>&nbsp;</p>"

#define J_TEST_TEXT1 "<SCRIPT LANGUAGE=\"JavaScript\"><!-- \
 \
name = \"cookie_test\"; \n \
    s = (new Date().getSeconds()); \
    document.cookie = name + \"=\" + s; \
\n \
    dc = document.cookie; \
    prefix = name + \"=\"; \
    begin = dc.indexOf(\"; \" + prefix); \
\n \
    if (begin == -1) { \
        begin = dc.indexOf(prefix); \
        if (begin != 0) returned = \"\"; \
    } else \
        begin += 2; \
    end = document.cookie.indexOf(\";\", begin); \
\n \
    if (end == -1) \
        end = dc.length; \
    returned = unescape(dc.substring(begin + prefix.length, end)); \
\n \
if ( returned == s ) { \
"

#define J_TEST_TEXT2 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">A problem has been detected!</font></B></P>\"); \
    document.write(\"<p><b><font size=\\\"+1\\\">Either you tried to use the BACK button to return to pages you\"); \
    document.write(\" visited before the UW NetID login page, or the URL address you opened contains a shortened\"); \
    document.write(\" domain name. </font></b></p>\"); \
    document.write(\"<p>Review <A HREF=\\\"http://www.washington.edu/computing/web/login-problems.html\\\">Common\"); \
    document.write(\" Problems With the UW NetID Login Page</A> for further advice.</p>\"); \
    document.write(\"<p>&nbsp;</p>\"); \
"

#define J_TEST_TEXT3 "    document.cookie = name + \"=; expires=Thu, 01-Jan-70 00:00:01 GMT\"; \
} \
else { \
"

#define J_TEST_TEXT4 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">This browser doesn't accept cookies!</font></B></P>\"); \
    document.write(\"<p><b><font size=\\\"+1\\\">Your browser must <a href=\\\"http://www.washington.edu/computing/web/cookies.html\\\">accept cookies</a> in\"); \
    document.write(\" order to use the UW NetID login page.</font></b></p>\"); \
    document.write(\"<p>&nbsp;</p>\"); \
"

#define J_TEST_TEXT5 "} \
 \
// --> \
</SCRIPT> \
"

#define NOTOK_NO_G_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P>\
\
<p><b><font size=\"+1\">Either you tried to use the BACK button to return to pages you visited before the UW NetID login page, or the URL address you opened contains a shortened domain name. </font></b></p>\
\
<p>Review <A HREF=\"http://www.washington.edu/computing/web/login-problems.html\">Common Problems With the UW NetID Login Page</A> for further advice.</p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_FORMMULTIPART_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P> \
\
<p><b><font size=\"+1\">The resource you requested requires \"multipart/form-data\" capabilities not supported by the UW NetID \"weblogin\" service. Please email <a href=\"mailto:help@cac.washington.edu\">help@cac.washington.edu</a> for further assistance.</font></b></p>\
\
"

#define NOTOK_BAD_AGENT_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">This browser is either incompatible or has serious security flaws.</font></B></P>\
\
<p><b><font size=\"+1\">Please upgrade to the most recent version of either <A HREF=\"http://home.netscape.com/computing/download/index.html\">Netscape Navigator</A>, <A HREF=\"http://www.microsoft.com/windows/ie/default.htm\">Internet Explorer</A>, or <A HREF=\"http://www.opera.com/\">Opera</A>.  "

#define NOTOK_BAD_AGENT_TEXT2 "<P>\
\
Please email <a href=\"mailto:help@cac.washington.edu\">help@cac.washington.edu</a> for further assistance.</font></b></p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_GENERIC_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P> \
\
<p>Review <A HREF=\"http://www.washington.edu/computing/web/login-problems.html\">Common Problems With the UW NetID Login Page</A> for further advice.</p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_NEEDSSL_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P> \n\
<P>This service requires a SSL protected connection.<BR>\n\
"

/* how big can a filled-in template be? */
#define MAX_EXPANDED_TEMPLATE_SIZE (110*1024)

#endif   /* PUBCOOKIE_LOGIN_CGI */
