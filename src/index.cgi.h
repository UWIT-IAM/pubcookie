/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
  $Id: index.cgi.h,v 1.49 2004-04-13 02:36:04 jteaton Exp $
 */

#ifndef PUBCOOKIE_LOGIN_CGI
#define PUBCOOKIE_LOGIN_CGI

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

/* cgic---needed for typenames */
#ifdef HAVE_CGIC_H
# include <cgic.h>
#endif /* HAVE_CGIC_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#include "security.h"

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
    int		hide_user;
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
    int		pre_sess_token;
    int		session_reauth;
    int		duration;
    char	*first_kiss;
    int		reply;
    int		alterable_username;
    int		pinit;
    int		pre_sess_tok;   
    char        *check_error;
    char        *relay_uri;
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
void abend(pool *, char *);
int cookie_test(pool *, const security_context *, login_rec *, login_rec *);
void notok(pool *, void (*)() );
void print_http_header(pool *);
void notok_need_ssl(pool *);
void notok_formmultipart(pool *);
void notok_generic(pool *);
void notok_bad_agent(pool *);
void print_login_page_part1(pool *,char *);
void print_login_page_part5(pool *);
int check_user_agent(pool *);
void log_message(pool *,const char *, ...);
void log_error(pool *,int, const char *, int, const char *, ...);
void clear_error(pool *,const char *, const char *);
void print_uwnetid_logo(pool *);
login_rec *verify_unload_login_cookie (pool *, const security_context *, login_rec *);
int create_cookie(pool *, const security_context *, char *, char *, char *, char, char, int, time_t, 
		time_t, char *, const char *host, int);
int get_cookie(pool *p, char *name, char *result, int max);
login_rec *get_query(pool *);
char *check_login(pool *, login_rec *, login_rec *);
char *check_l_cookie(pool *, const security_context *, login_rec *, login_rec *);
void print_redirect_page(pool *, const security_context *, login_rec *, login_rec *);
char *url_encode(pool *, char *);
char *get_cookie_created(pool *, char *);
char *decode_granting_request(pool *, char *, char **peerp);
const char *login_host(pool *);
const char *enterprise_domain(pool *);
int set_pinit_cookie(pool *);
int clear_pinit_cookie(pool *);
char *get_string_arg(pool *, char *name, cgiFormResultType(*f)());

/* print part of the HTML */
void print_html(pool *, const char *format, ...);
/* print it from the template "fname" */
void tmpl_print_html(pool *, const char *fpath, const char *fname,...);

void ntmpl_print_html(pool *p, const char *fname, ...);

/* print part of the HTTP headers */
void print_header(pool *, const char *format, ...);

#define RIDE_FREE_TIME (10 * 60)
#define LOGIN_DIR "/"
#define THIS_CGI "cindex.cgi"
#define REFRESH "0"
#define DEFAULT_LOGIN_EXPIRE (8 * 60 * 60)
#define APP_LOGOUT_STR "app_logout_string"
#define APP_LOGOUT_STR_SEP '-'

#define STATUS_HTML_REFRESH "<meta http-equiv=\"Refresh\" content=\"%d;URL=/?countdown=%d\">"
#define STATUS_INIT_SIZE 256

/* the pinit cookie is used to transition from a pinit login to 
   a pinit responce */
#define PBC_PINIT_COOKIENAME "pinit"

/* some messages about people who hit posts and don't have js on */
#define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"

#define TROUBLE_CREATING_COOKIE "Trouble creating cookie.  Please re-enter."
#define PROBLEMS_PERSIST "If problems persist contact help@cac.washington.edu."

/* special strings about time remaining */
#define REMAINING_EXPIRED "expired"
#define REMAINING_UNKNOWN "unknown"

/* tags the request as a reply from the form */
#define FORM_REPLY 1

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

/* text */

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
