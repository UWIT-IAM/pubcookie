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

    this is the pubcookie login cgi, YEAH!

 */

/*
    $Id: index.cgi.c,v 1.3 1999-11-19 18:58:29 willey Exp $
 */


/* LibC */
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* openssl */
#include <pem.h>
/* krb5  */
#include <com_err.h>
#include <krb5.h>
/* securid */
//#include <pwd.h>
//#include <grp.h>
//#include <sys/param.h>
//#include <sys/types.h>
//#include <sys/time.h>
//#include <sys/resource.h>
//#include <netinet/in.h>
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
/* cgic */
#include <cgic.h>

  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*	general utility thingies                                            */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

/* this returns first cookie for a given name */
int get_cookie(char *name, char *result, int max)
{
    char	*s;
    char	*p;
    char	*target;
    char	*wkspc;

    if( !(target = malloc(PBC_20K)) ) {
        abend("out of memory");
    }

    /* get all the cookies */
    if( !(s = getenv("HTTP_COOKIE")) ){
        log_message("looking for %s cookie, but found no cookies", name);
        notok(notok_no_g_or_l);
        return(FAIL);
    }

    /* make us a local copy */
    strncpy( target, s, PBC_20K-1 );

    if( !(wkspc=strstr( target, name )) ) {
        log_message("looking for %s cookie, but didn't find it", name);
        notok(notok_no_g_or_l);
        return(FAIL);
    }

    /* get rid of the <name>= part from the cookie */
    p = wkspc = wkspc + strlen(name) + 1;
    while(*p) {
        if( *p == ';' ) {
            *p = '\0';
            break;
        }
        p++;
    }

    strncpy( result, wkspc, max );
    free( target );
    return( OK );

}

char *get_string_arg(char *name, cgiFormResultType (*f)())
{
    int			length;
    char		*s;

    cgiFormStringSpaceNeeded(name, &length);
    s = calloc(length+1, sizeof(char));

    if( f(name, s, length+1) != cgiFormSuccess ) {
        return(NULL);
    } 
    else {
        return(s);
    }

}

int get_int_arg(char *name)
{
    int		i;

    if( cgiFormInteger(name, &i, 0) != cgiFormSuccess ) {
        return(0);
    } 
    else {
        return(i);
    }

}

char *clean_username(char *in)
{
    char	*p;
    int		word_start = 0;

    p = in;
    while(*p) {
        /* no email addresses or full principals */
        if(*p == '@')
            *p = '\0';

        /* no spaces at the beginning of the username */
        if(*p == ' ' && !word_start)
            in = p + 1;
        else
            word_start = 1;

        /* no spaces at the end */
        if(*p == ' ' && word_start) {
            *p = '\0';
            break;
        }

        p++;
    }
 
    return(in);

}

login_rec *load_login_rec(login_rec *l) 
{

fprintf(stderr, "in load_login_rec\n");

    /* make sure the username is a uwnetid */
    if( (l->user=get_string_arg("user", NO_NEWLINES_FUNC)) )
        l->user = clean_username(l->user);

    l->pass 		= get_string_arg("pass", NO_NEWLINES_FUNC);
    l->pass2 		= get_string_arg("pass2", NO_NEWLINES_FUNC);
    l->post_stuff	= get_string_arg("post_stuff", YES_NEWLINES_FUNC);

    l->args 		= get_string_arg("eight", YES_NEWLINES_FUNC);
    l->uri 		= get_string_arg("seven", NO_NEWLINES_FUNC);
    l->host 		= get_string_arg("six", NO_NEWLINES_FUNC);
    l->method 		= get_string_arg("five", NO_NEWLINES_FUNC);
    l->version 		= get_string_arg("four", NO_NEWLINES_FUNC);
    l->creds      	= get_int_arg("three") + 48;
    l->appid 		= get_string_arg("two", NO_NEWLINES_FUNC);
    l->appsrvid 	= get_string_arg("one", NO_NEWLINES_FUNC);
    l->fr 		= get_string_arg("fr", NO_NEWLINES_FUNC);

fprintf(stderr, "finished load_login_rec\n");

    return(l);

}

char *url_encode(char *in)
{
    char	*out;
    char	*p;

    if( !(out = malloc(PBC_4K)) ) {
        abend("out of memory");
    }

    strncpy(out, in, PBC_4K);

    p = out;
    while( *p ) {
        switch(*p) {
        case ' ':
            *p = '+';
            break;
        case '!':
            *p = '%'; *(++p) = '2'; *(++p) = '1';
            break;
        case '"':
            *p = '%'; *(++p) = '2'; *(++p) = '2';
            break;
        case '#':
            *p = '%'; *(++p) = '2'; *(++p) = '3';
            break;
        case '$':
            *p = '%'; *(++p) = '2'; *(++p) = '4';
            break;
        case '%':
            *p = '%'; *(++p) = '2'; *(++p) = '5';
            break;
        case '&':
            *p = '%'; *(++p) = '2'; *(++p) = '6';
            break;
        case '+':
            *p = '%'; *(++p) = '2'; *(++p) = 'B';
            break;
        case ':':
            *p = '%'; *(++p) = '3'; *(++p) = 'A';
            break;
        case ';':
            *p = '%'; *(++p) = '3'; *(++p) = 'B';
            break;
        case '=':
            *p = '%'; *(++p) = '3'; *(++p) = 'D';
            break;
        case '?':
            *p = '%'; *(++p) = '3'; *(++p) = 'F';
            break;
        }
        p++;
    }

    return(out);

}

void log_message(const char *format, ...) 
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format), "%s: %s\n", 
			ANY_LOGINSRV_MESSAGE, format);
    vsnprintf(message, sizeof(message), new_format, args);
    va_end(args);
    libpbc_debug(message);

}

void send_pilot_message(char *message) 
{

//    my $cmd = "$send_pilot_cmd pcookie_login:TRIG:1:pubcookie: $message: this trigger will have to manually cleared";
//    $cmd =~ s/(['"!])/\\$1/;
//    log_message("sending message to pilot $cmd");
//    `$cmd`;

}

void log_error(const char *format,...)
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format), "%s: %s", SYSERR_LOGINSRV_MESSAGE, format);
    vsnprintf(message, sizeof(message), new_format, args);
    log_message(message);
    send_pilot_message(message);
    va_end(args);

}

void abend(char *message) 
{

    log_error(message);
    notok(notok_generic);
    exit(0);

}

void print_out(char *format,...)
{
    va_list	args;

    va_start(args, format);
    vprintf(format, args);
    vfprintf(stderr, format, args);
    va_end(args);

}

char *get_my_hostname() 
{
    struct utsname	myname;

    if ( uname(&myname) < 0 )
        log_error("problem doing uname lookup");

    return(strdup(myname.nodename));

}

char *get_domain_hostname() 
{
    char	host[PBC_1K];

    strncpy(host, getenv ("HTTP_HOST"), strlen(host));

    if( !host )
        return ("weblogin.cac.washington.edu");

    /* if this is a test server use the test name */
    if ( !strncmp(host,"pcookiel3",9) || !strncmp(host,"weblogintest",12) )
        return ("weblogintest.cac.washington.edu");
    else
        return ("weblogin.cac.washington.edu");

}

int has_login_cookie()
{
    if( getenv("HTTP_COOKIE") && strstr(getenv("HTTP_COOKIE"), PBC_L_COOKIENAME) )
        return(1);
    else
        return(0);

}

int get_next_serial()
{
    return(23);

//
//
//
//
//
//
//

}

char *get_granting_request() 
{
    char	*cookie;

    if( !(cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }

    if( !get_cookie(PBC_G_REQ_COOKIENAME, cookie, PBC_4K-1) ) {
        return(NULL);
    }

    return( cookie );

}

char *decode_granting_request(char *in)
{
    char	*out;

    out = strdup(in);    
    base64_decode(in, out);
    return(out);

}


  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*	main line                                                           */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

int cgiMain() 
{
    login_rec	*l;
    char	*res;
    char	message[PBC_4K];

    /* bail if not ssl */
    if( !getenv("HTTPS") || strcmp( getenv("HTTPS"), "on" ) ) { 
        notok(notok_need_ssl);
        exit(0);
    }

    /* check to see what cookies we have */
    /* if there is an error print the error page */
    if( !cookie_test() )
        exit(0);

    /* get the arguments to this cgi, whether they are from submitting */
    /* the login page or from from the granting request cookie         */
    /* you call tell the difference since the submitted one will have  */
    /* user and pass filled in                                         */
    /* malloc and populate login_rec                                   */
    l = get_query(); 

fprintf(stderr, "after get_query\n");

    /* check the user agent */
    if ( !check_user_agent() ) {
        log_message("bad agent: %s host: %s uri: %s", cgiUserAgent, 
			l->host, l->uri);
        notok(notok_bad_agent);
        exit(0);
    }

fprintf(stderr, "after user agent get_query\n");

    /* allow for older versions that don't have froce_reauth */
    if ( !l->fr ) {
        l->fr = strdup("NFR");
    }

    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
    /*                                                                   */
    /* the following text should be updated for support for POST         */
    /*                                                                   */
    /* four cases for the main thingie                                   */
    /*   - first time or force_reauth:                                   */
    /*         in: no L cookie, bunch of GET data                        */
    /*               OR force_reauth info in GET                         */
    /*         out: the login page (includes data from get)              */
    /*                                                                   */
    /*   - not first time (have L cookie) but L cookie expired or invalid*/
    /*         in: expired or invalid L cookie, bunch of GET data        */
    /*         out: the login page (includes data from get)              */
    /*                                                                   */
    /*   - not first time (have L cookie) L cookie not expired and valid */
    /*         in: valid L cookie, bunch of GET data                     */
    /*         out: L & G cookies redirect (username comes from cookie)  */
    /*                                                                   */
    /*   - POST from login page                                          */
    /*         in: POST data that include creds                          */
    /*         process: validate creds                                   */
    /*         out: if successful L & G cookies redirect else login page */
    /*                                                                   */
    /* the above text should be updated for support for POST             */
    /*                                                                   */
    /*                                                                   */
    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

    /* the main logic */
    if ( l->user ) {                           /* a reply from the login page */
fprintf(stderr, "wohooo!, an answer from the login page!");
        res = check_login(l);
        if( strcmp(res, CHECK_LOGIN_RET_SUCCESS) ) {
            log_message("Authentication failed: %s type: %c %s", l->user, l->creds, res);
            if( !strcmp(res, "Authentication Failed") ) {
                snprintf(message, sizeof(message), "%s%s%s<P>%s",
                    PBC_EM1_START,
                    AUTH_FAILED_MESSAGE1,
                    PBC_EM1_END, 
                    AUTH_FAILED_MESSAGE2);
            }
            else {
                log_error("Login problem: %s", res);
                snprintf(message, sizeof(message), "%s%s%s<P>",
                    PBC_EM1_START,
                    AUTH_TROUBLE,
                    PBC_EM1_END);
            }
            print_login_page(message, "bad auth", l->creds, NO_CLEAR_LOGIN);
            exit(0);
        }
        log_message("Authentication success: %s type: %d", l->user, l->creds);
    }
    else if( strcmp(l->fr,"NFR") ) {           /* force reauth */
        log_message("user was forced to reauth by %s at %s", l->host, l->appid);
        print_login_page(PRINT_LOGIN_PLEASE, "force reauth", l->creds, YES_CLEAR_LOGIN);
        exit(0);
    }
    else if ( !has_login_cookie() ) {          /* no l cookie, must login */
char *s;
s = malloc(2048);
fprintf(stderr, "no login cookie, true?\n");
get_cookie(PBC_L_COOKIENAME, s, 2048);
fprintf(stderr, "the cookies %s\n", s);
        print_login_page(PRINT_LOGIN_PLEASE, "no L cookie yet", l->creds, NO_CLEAR_LOGIN);
        exit(0);
    }
    else if ( (res=check_l_cookie(l)) ) {      /* problem w/ the l cookie*/
        log_message("Login cookie bad: %s", res);
        print_login_page(PRINT_LOGIN_PLEASE, res, l->creds, YES_CLEAR_LOGIN);
        exit(0);
    }

    /* the reward for a hard days work                                        */
    log_message("Issuing cookies for %s at %s on %s at %s", 
 			l->user, cgiRemoteAddr, l->host, l->appid);

    /* generate the cookies and print the redirect page                       */
    print_redirect_page(l);

    return(1);  
}


void print_login_page(char *message, char *reason, char creds, int need_clear_login)
{
    char	*word;
    char	*field_label1 = NULL;
    char	*field_label2 = NULL;
    char	input_type1[9];
    char	input_type2[9];
    char	*hostname = strdup(get_domain_hostname());

    switch (creds) {
    case '1':
        field_label1 = strdup(PROMPT_UWNETID);
        word = strdup("password");
        strcpy(input_type1, "PASSWORD");
        break;
    case '2':
        field_label1 = strdup("Invalid request\n");
        word = strdup("INVALID REQUEST");
        strcpy(input_type1, "TEXT");
        break;
    case '3':
        field_label2 = strdup(PROMPT_SECURID);
        field_label1 = strdup(PROMPT_UWNETID);
        word = strdup("password and SecurID");
        strcpy(input_type1, "TEXT");
        strcpy(input_type2, "TEXT");
        break;
    default:
        field_label1 = strdup(PROMPT_UWNETID);
        word = strdup("password");
        strcpy(input_type1, "TEXT");
        break;
    }

    print_out("Content-Type: text/html\n");
    if( need_clear_login ) 
        print_out("Set-Cookie: %s=clear; domain=%s; path=%s; expires=Fri, 11-Jan-1990 00:00:01 GMT; secure\n", PBC_L_COOKIENAME, hostname, LOGIN_DIR);
    print_out("\n");

    print_login_page_part1(YES_FOCUS);

    print_out("<P>%s</P>\n", message);
    print_out("<!-- -- %s -- -->\n", reason);

    /* if this is a login then print the login stuff */
    if( !strcmp(message, PRINT_LOGIN_PLEASE) ) {
        print_login_page_part2a();
    }
    print_login_page_part2b();

    print_login_page_part3(word);         /* the form */

    print_out("%s\n<INPUT TYPE=\"%s", field_label1, input_type1);
    print_out("\" NAME=\"pass\" SIZE=\"20\">\n<P>\n");

    if( field_label2 ) {
        print_out("%s<INPUT TYPE=\"%s", field_label2, input_type2);
        print_out("\" NAME=\"pass2\" SIZE=\"20\">\n");
    }

    print_login_page_part4();

    print_login_page_part_expire_info();

    print_login_page_part5();

}

char *check_login_uwnetid(char *user, char *pass)
{
    if( auth_kdc(user, pass) == OK )
        return(CHECK_LOGIN_RET_SUCCESS);
    else
        return(CHECK_LOGIN_RET_FAIL);

}

char *check_login_securid(char *user, char *sid)
{
        return(CHECK_LOGIN_RET_SUCCESS);

}

/* successful auth returns CHECK_LOGIN_RET_SUCCESS                            */
char *check_login(login_rec *l)
{
    char	*ret;

    if( !(ret = malloc(100)) ) {
        abend("out of memory");
    }

    strcpy(ret, CHECK_LOGIN_RET_BAD_CREDS);

    if( l->creds == '1' ) {
        strcpy(ret, check_login_uwnetid(l->user, l->pass));
    }
    else if( l->creds == '3' ) {
        strcpy(ret, check_login_securid(l->user, l->pass2));
        if( !strcmp(ret, CHECK_LOGIN_RET_SUCCESS) ) {
            strcpy(ret, check_login_uwnetid(l->user, l->pass));
        }
        else {
            return ret;
        }
    }

    return(ret);

}


/* returns NULL if o.k.                                                       */
/*   else a description of the failure                                        */
char *check_l_cookie(login_rec *l)
{
    char	*cookie;
    login_rec	*lc;
    time_t	t;
    char	*g_version;
    char	*l_version;

fprintf(stderr, "in check_l_cookie \n");

    if( !(cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }

    /* get the login request cookie */
    if( !get_cookie(PBC_L_COOKIENAME, cookie, PBC_4K-1) ) {
        abend("no login cookies");
        return 0;
    }

fprintf(stderr, "in check_l_cookie l cookie is %s\n", cookie);

    /* $verify_pgm takes arguments on the command line         */
    /* the arguments are <cookie type> <crypt key> <cert file> */
    /* and the cookie on stdin, it returns the information     */
    /* from teh cookie on stdout                               */

    lc = verify_login_cookie(cookie, l);

    if( !lc ) {
        log_message("couldn't deal with cookie %s", cookie);
        return("couldn't decode login cookie");
    }

fprintf(stderr, "in check_l_cookie ready to look at cookie contents %s\n", lc->user);

    /* look at what we got back from the cookie */
    if( ! lc->user ) {
        log_error("no user from login cookie? user from g_req: %s", l->user);
        return "malformed";
    }

    if( (lc->create_ts + EXPIRE_LOGIN) < (t=time(NULL)) ) {
        log_message("expired login cookie: created: %d timeout: %dsecs now: %d",
			lc->create_ts, EXPIRE_LOGIN, t);
        return "expired";
    }

fprintf(stderr, "in check_l_cookie ready to look at cookie creds %c\n", lc->creds);
    if( lc->creds != l->creds ) {
        if( l->creds == '1' ) {
            if( lc->creds != '3' ) {
                log_error("wrong_creds: from login cookie: %s from request: %s",
			lc->creds, l->creds);
                return("wrong_creds");
            }
        }
        else {
            log_error("wrong_creds: from login cookie: %s from request: %s", 
			lc->creds, l->creds);
            return("wrong_creds");
        }
    }

    l_version = lc->version; g_version = l->version;
    if( *l_version != *g_version ) {
        log_error("wrong major version: from l cookie %s, from g_req %s for host %s", 
			l_version, g_version, l->host);
        return("wrong major version");
    }
    if( *(l_version+1) != *(g_version+1) ) {
        log_error("warn: wrong minor version: from l cookie %s, from g_req %s for host %s", 
			l_version, g_version, l->host);
    }

    l->user = lc->user;
    l->creds = lc->creds;
    free(cookie);
fprintf(stderr, "in check_l_cookie everything is o'tay\n");
    return((char *)NULL);
}


  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*	functions                                                           */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

void print_j_test() 
{

    print_out("%s", J_TEST_TEXT1);
    print_out("%s", J_TEST_TEXT2);
    print_out("%s", J_TEST_TEXT3);
    print_out("%s", J_TEST_TEXT4);
    print_out("%s", J_TEST_TEXT5);

}

void notok_no_g_or_l() 
{
    print_j_test();

    print_out("<NOSCRIPT>\n");

    print_out("%s", NOTOK_NO_G_OR_L_TEXT1);

    print_out("</NOSCRIPT>\n");

}

void notok_no_g() 
{
    print_out("%s", NOTOK_NO_G_TEXT1);

}

void notok_formmultipart() 
{
    print_out("%s", NOTOK_FORMMULTIPART_TEXT1);

}

void notok_need_ssl() 
{
    print_out("%s", NOTOK_NEEDSSL_TEXT1);
    log_message("host %s came in on a non-ssl port, why?", cgiRemoteAddr);
}

void notok_bad_agent() 
{
    print_out("%s", NOTOK_BAD_AGENT_TEXT1);
    print_out("The browser you are using identifies itself as:<P><TT></TT>",
                 cgiUserAgent);
    print_out("%s", NOTOK_BAD_AGENT_TEXT2);

}

void notok_generic() 
{
    print_out("%s", NOTOK_GENERIC_TEXT1);

}

/* prints the error pages                                                     */
//# 1 - no cookies or non-fqdn 
//#     (http://staff.washington.edu/dors/projects/login/problem1.html)
//# 2 - backing in or non-fqd
//#     (http://staff.washington.edu/dors/projects/login/problem2.html)
//# 3 - no cookies!
//#     (http://staff.washington.edu/dors/projects/login/problem3.html)
//# 4 - multipart/form-data
//#     (http://staff.washington.edu/dors/projects/login/problem4.html)
//# 5 - not ssl, impossible but we still look for it.
//#
void notok ( void (*notok_f)() )
{
    print_out("Content-Type: text/html\n");

    /* if we got a form multipart cookie, reset it */
    if ( getenv("HTTP_COOKIE") && strstr(getenv("HTTP_COOKIE"), PBC_FORM_MP_COOKIENAME) ) {
        print_out("Set-Cookie: %s=done; domain=.washington.edu; path=/; expires=Fri, 11-Jan-1990 00:00:01 GMT", PBC_FORM_MP_COOKIENAME);
    }

    print_out("\n");

    print_login_page_part1(NO_FOCUS);

    notok_f();

    print_login_page_part5();

}


int cookie_test() 
{
    char        *cookies;

    /* get the cookies */
    if ( !(cookies = getenv("HTTP_COOKIE")) ){
        notok(notok_no_g_or_l);
        return(0);
    }
    
    /* we don't currently handle form-multipart */
    /* the formmultipart cookie is set by the module */
    if ( strstr(cookies, PBC_FORM_MP_COOKIENAME) ) {
        notok(notok_formmultipart);
        return(0);
    }

    if ( !strstr(cookies, PBC_G_REQ_COOKIENAME) ) {

        if ( !strstr(cookies, PBC_L_COOKIENAME) ) {
            log_message("no granting req or login cookie from %s", getenv("REMOTE_ADDR"));
            notok(notok_no_g_or_l);
            return(0);
        }
        else {
            log_message("no granting req, connection from %s", getenv("REMOTE_ADDR"));
            notok(notok_no_g);
            return(0);
        }
    }
    
    free(cookies);
    return(1);
}

/*	################################### print copyright                   */
void print_copyright()
{
    print_out("<address>&#169; 1999 University of Washington</address>\n","");

}


/*	################################### The beginning of the table        */
void print_table_start()
{
    print_out("<TABLE CELLPADDING=0 CELLSPACING=0 BORDER=0 WIDTH=520>\n","");

}

/*	################################### UWNetID Logo                      */
void print_uwnetid_logo()
{
    print_out("<TR>\n<TD WIDTH=300 VALIGN=\"MIDDLE\">\n","");
    print_out("<IMG SRC=\"/images/login.gif\" ALT=\"UW NetID Login\" HEIGHT=\"64\" WIDTH=\"208\">\n","");

}

/*       ################################### part 1                           */
void print_login_page_part1(int focus)
{
    print_out("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n","");
    print_out("<HTML>\n","");
    print_out("<HEAD>\n","");
    print_out("<TITLE>UW NetID Login</TITLE>\n","");
    print_out("</HEAD>\n","");

    if( focus ) {
        print_out("<BODY BGCOLOR=\"#FFFFFF\" onLoad=\"document.query.user.focus()\">\n","");
    }
    else {
        print_out("<BODY BGCOLOR=\"#FFFFFF\">\n","");
    }

    print_out("<CENTER>\n","");

    print_table_start();
    print_uwnetid_logo();

}

/*	################################### part 2a                           */
void print_login_page_part2a()
{
    print_out("<P>The resource you requested requires you to log in with your UW NetID and password.</P>\n");

}

/*	################################### part 2b                           */
void print_login_page_part2b()
{
    print_out("<p>Need a UW NetID or forget your password? Go to the <a href=\"http://www.washington.edu/computing/uwnetid/\">UW NetID Home Page</a> for help.</p>\n");
    print_out("<p>Please send email to <a href=\"mailto:help@cac.washington.edu\"> help@cac.washington.edu</a> to report problems.</p>\n");
    print_out("</TD>\n");

}



/*	################################### part 3                            */
void print_login_page_part3(char *word) 
{
    print_out("<TD WIDTH=9>&nbsp;</TD>\n\n");
    print_out("<TD WIDTH=2 BGCOLOR=\"#000000\">");
    print_out("<IMG SRC=\"/images/1pixffcc33iystpiwfy.gif\"");
    print_out(" WIDTH=\"1\" HEIGHT=\"1\" ALIGN=\"BOTTOM\" ALT=\"\"></TD>\n\n");
    print_out("<TD WIDTH=9>&nbsp;</TD>\n\n");
    print_out("<TD WIDTH=200 VALIGN=\"MIDDLE\">\n");
    print_out("<FORM METHOD=\"POST\" ACTION=\"/%s\" ", THIS_CGI);
    print_out("ENCTYPE=\"application/x-www-form-urlencoded\"");
    print_out("NAME=\"query\">\n");
    print_out("<p>Enter your UW NetID and %s below, ", word);
    print_out("then click the Login button.</p>\n");
    print_out("<P>\n");
    print_out("<B>UW NetID:</B><BR>\n");
    print_out("<INPUT TYPE=\"TEXT\" NAME=\"user\" SIZE=\"20\">\n");
    print_out("<BR>\n");
    print_out("<P>\n");

}

/*	################################### part 4                            */
void print_login_page_part4(login_rec *l)
{

    print_out("<P>\n");
    print_out("<STRONG><INPUT TYPE=\"SUBMIT\" NAME=\"submit\" VALUE=\"Login\"></STRONG>\n");
    print_out("<INPUT TYPE=\"hidden\" NAME=\"one\" VALUE=\"%s\">\n", 
		(l->appsrvid ? l->appsrvid : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"two\" VALUE=\"%s\">\n",
		(l->appid ? l->appid : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"three\" VALUE=\"%c\">\n", l->creds);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"four\" VALUE=\"%s\">\n",
		(l->version ? l->version : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"five\" VALUE=\"%s\">\n",
		(l->method ? l->method : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"six\" VALUE=\"%s\">\n",
		(l->host ? l->host : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"seven\" VALUE=\"%s\">\n",
		(l->uri ? l->uri : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"eight\" VALUE=\"%s\">\n",
		(l->args ? l->args : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"fr\" VALUE=\"%s\">\n",
		(l->fr ? l->fr : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"post_stuff\" VALUE=\"%s\">\n",
		(l->post_stuff ? l->post_stuff : "") );
    print_out("</FORM>\n");
    print_out("</TD>\n");

}

/*	################################### part 5                            */
void print_login_page_part5() 
{
    print_out("</TR>\n");
    print_out("<TR>\n");
    print_out("<TD COLSPAN=5 ALIGN=CENTER>\n");

    print_copyright();

    print_out("</td>\n");
    print_out("</tr>\n");
    print_out("</TABLE>\n");
    print_out("</CENTER>\n");
    print_out("</BODY></HTML>\n");
}

/*	################################### part expire_info                  */
void print_login_page_part_expire_info()
{
    print_out("</TR>\n<TR>\n");

    print_out("<TD COLSPAN=5 ALIGN=CENTER>\n");

    print_out("<p><br>UW NetID login lasts 8 hours or until you exit your browser. To protect your privacy, <STRONG>exit your Web browser</STRONG> when you are done with this session.</p>\n");

    print_out("</td>\n");

}

char *to_lower(char *in)
{
    char	*p;

    for(p = in; *p; p++)
        *p = tolower(*p);

    return(in);

}

void clean_ok_browsers_line(char *in)
{
    char	*p;

    for(p = in; *p; p++) {
        *p = tolower(*p);
        if( *p == '\n' ) 
            *p-- = '\0';
    }

}

int check_user_agent()
{
    char        line[PBC_1K];
    char        agent_clean[PBC_1K];
    FILE	*ifp;

    if ( !(ifp = fopen(OK_BROWSERS_FILE, "r")) ) {
        log_error("can't open ok browsers file: %s, continuing", OK_BROWSERS_FILE);
        return(0);
    }

    /* make the user agent lower case */
    strncpy( agent_clean, cgiUserAgent, sizeof(agent_clean) );
    clean_ok_browsers_line(agent_clean);

    while( fgets(line, sizeof(line), ifp) != NULL ) {
        clean_ok_browsers_line(line);
        if( line[0] == '#' )
            continue;
        if( strstr( agent_clean, line ) ) {
            return(1);
        }
    }

    return(0);

}


void print_redirect_page(login_rec *l)
{
    int		serial = 0;
    char	*submit_value = NULL;
    char	*g_cookie;
    char	*l_cookie;
    char	*redirect_uri;
    char	*message;
    char	*redirect_dest = NULL;
    char	g_set_cookie[PBC_1K];
    char	l_set_cookie[PBC_1K];
    char	clear_g_req_cookie[PBC_1K];
    int		g_res, l_res;

fprintf(stderr, "in print_redirect_page\n");

    if( !(redirect_dest = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    if( !(message = malloc(PBC_1K)) ) {
        abend("out of memory");
    }
    if( !(g_cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    if( !(l_cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    serial = get_next_serial();

    /* cook up them cookies */
    l_res = create_cookie(url_encode(l->user),
                          url_encode(l->appsrvid),
                          url_encode(l->appid),
                          PBC_COOKIE_TYPE_L,
                          l->creds,
                          serial,
                          l_cookie,
                          PBC_4K);
    g_res = create_cookie(url_encode(l->user),
                          url_encode(l->appsrvid),
                          url_encode(l->appid),
                          PBC_COOKIE_TYPE_G,
                          l->creds,
                          serial,
                          g_cookie,
                          PBC_4K);

fprintf(stderr, "in print_redirect_page got cookies\n");

    if ( !l_res || !g_res ) {
          sprintf( message, "%s%s%s%s%s%s",
		PBC_EM1_START,
		TROUBLE_CREATING_COOKIE,
		PBC_EM1_END,
      		PBC_EM2_START,
		PROBLEMS_PERSIST,
         	PBC_EM2_END);
          print_login_page(message, "cookie create failed", l->creds, 
		NO_CLEAR_LOGIN);
          log_error("Not able to create cookie for user %s at %s-%s", l->user, 
		l->appsrvid, l->appid);
          free(message);
          return;
    }

fprintf(stderr, "in print_redirect_page cookies are ok\n");

    snprintf( g_set_cookie, sizeof(g_set_cookie), 
		"Set-Cookie: %s=%s; domain=.washington.edu; path=/; secure", 
		PBC_G_COOKIENAME,
                g_cookie);
    snprintf( l_set_cookie, sizeof(l_set_cookie), 
		"Set-Cookie: %s=%s; domain=%s; path=%s; secure", 
		PBC_L_COOKIENAME,
                l_cookie,
                get_domain_hostname(),
                LOGIN_DIR);
    snprintf( clear_g_req_cookie, sizeof(g_set_cookie), 
		"Set-Cookie: %s=done; domain=.washington.edu; path=/; expires=%s",
		PBC_G_REQ_COOKIENAME);


    /* whip up the url to send the browser back to */
    if( !strcmp(l->fr, "NFR") )
        redirect_uri = l->uri;
    else
        redirect_uri = l->fr;

fprintf(stderr, "in print_redirect_page uri is %s\n", redirect_uri);

    snprintf(redirect_dest, PBC_4K, "https://%s%s%s", 
		l->host, (*redirect_uri == '/' ? "" : "/"), redirect_uri);

    if( l->args ) {
        char	*args_enc = NULL; 

	base64_decode(l->args, args_enc);
        snprintf( redirect_dest, PBC_4K, "%s?%s", redirect_dest, args_enc );
    }

    log_message ("about to do redirect of %s for host %s, redirect is: %s", 
				l->user, l->host, redirect_dest);

    /* now blat out the redirect page */
    print_out("%s\n", g_set_cookie);
    print_out("%s\n", l_set_cookie);
    print_out("%s\n", clear_g_req_cookie);

    if ( l->post_stuff ) {
        /* incase we have a post */
//    my $g_req_args = new CGI;
//    $g_req_args->import_names('QP');
//    $post_stuff = $QP::post_stuff;


//#    print_out("Pragma: No-Cache\n");
//    print_out("Content-Type: text/html\n\n\n");
//    print_out("<HTML>");
//    # when the page loads click on the last element (which will always be the 
//    # submit) in the array of elements in the first, and only, form.
//    print_out("<BODY BGCOLOR=\"white\" onLoad=\"document.forms[0].elements[document.forms[0].elements.length-1].click()\">\n");
//    print_out("<CENTER>");
//    &print_table_start;
//    print_out("<TR><TD ALIGN=\"LEFT\">\n");
//    print_out("<FORM METHOD=\"POST\" ACTION=\"$redirect_dest\" ENCTYPE=\"application/x-www-form-urlencoded\" NAME=\"query\">\n");
//
//    my $post_args = new CGI($post_stuff);
//    $post_args->autoEscape(undef);
//    my $limitations_mentioned;
//    foreach my $name ( $post_args->param ) {
//        my $value = $post_args->param($name);
//        $name =~ s%^\s*HTTP/1.1 100 Continue\s*%%mi;
//        if ( $value =~ /"/ ) {
//            if ( ! $limitations_mentioned ) {
//                print_out("Certain limitations require that this be shown, please ignore it<BR>\n");
//                $limitations_mentioned++;
//            }
//            print_out("<TEXTAREA COLS=0 ROWS=0 NAME=\"$name\">\n$value</TEXTAREA>");
//            print_out("<P>\n");
//        }
//        else {
//            # we don't want to cover other people's submits
//            if ( $name eq "submit" )  {
//                $submit_value = $value;
//            }
//            else {
//                print_out("<INPUT TYPE=\"hidden\" NAME=\"$name\" VALUE='$value'>\n");
//            }
//        }
//    }
//
        print_out("</TD></TR>\n");
        print_uwnetid_logo();
        print_out("<P>");
        print_out("%s\n", PBC_POST_NO_JS_TEXT);
        print_out("</TD></TR></TABLE>\n");

        /* put submit at the bottom so it looks better and */
        if( submit_value )
            print_out("<INPUT TYPE=\"SUBMIT\" NAME=\"submit\" VALUE=\'%s\'>\n", submit_value);
        else
            print_out("<INPUT TYPE=\"SUBMIT\" VALUE=\"%s\">\n", PBC_POST_NO_JS_BUTTON);

        print_out("</FORM>\n");
        print_copyright();
        print_out("</CENTER>");
        print_out("</BODY></HTML>\n");
    }
    else {
        print_out("Content-Type: text/html\n\n\n");
        print_out("<HTML><HEAD>\n");
        print_out("<META HTTP-EQUIV=\"Refresh\" CONTENT=\"%s;URL=%s\">\n", REFRESH, redirect_dest);
        print_out("<BODY BGCOLOR=\"white\">");
        print_out("<!--redirecting to %s-->", redirect_dest);
        print_out("</BODY></HTML>\n");
    }

    free(g_cookie);
    free(l_cookie);
    free(message);
    free(redirect_dest);

}

login_rec *get_query() 
{
    login_rec		*l = malloc(sizeof(login_rec));
    char		*g_req;
    char		*g_req_clear;

    /* depending how we get to the cgi the arguments are either in the        */
    /* granting request or in a post from the login page                      */
    /*                                                                        */
    /* cgiParseFormInput will extract the arguments from the granting         */
    /* cookie string and make them available to subsequent cgic calls         */

    /* if there is a user field there it is a submit from a login */
    if( (l->user=get_string_arg("user", NO_NEWLINES_FUNC)) ) {
        l = load_login_rec(l);
    }
    else {
        if( !(g_req = get_granting_request()) ) {
            log_error("no granting request cookie");
            notok(notok_generic);
            return(NULL);
        }
        g_req_clear = decode_granting_request(g_req);

// ssw debug
fprintf(stderr, "this is the decoded greg %s\n", g_req_clear);

        if( cgiParseFormInput(g_req_clear, strlen(g_req_clear)) 
                   != cgiParseSuccess ) {
            log_error("couldn't parse the decoded granting request cookie");
            notok(notok_generic);
            return(NULL);
        }
        l = load_login_rec(l);
        free( g_req );
        free( g_req_clear );
    }

    /* we should always have apphost, cry if we don't */
    if( !(l->appid) ) {
        abend("submit from login page problem or granting request mangled");
    }

fprintf(stderr, "from login user: %s\n", l->user);
fprintf(stderr, "from login version: %s\n", l->version);
fprintf(stderr, "from login creds: %c\n", l->creds);
fprintf(stderr, "from login appid: %s\n", l->appid);
fprintf(stderr, "from login host: %s\n", l->host);
fprintf(stderr, "from login appsrvid: %s\n", l->appsrvid);
    return(l);

}

login_rec *verify_login_cookie (char *cookie, login_rec *l)
{
    md_context_plus     *ctx_plus;
    crypt_stuff         *c_stuff;
    pbc_cookie_data     *cookie_data;
    char		crypt_keyfile[PBC_4K];
    char		sign_keyfile[PBC_4K];
    login_rec		*new;

    new = malloc(sizeof(new));

    snprintf(crypt_keyfile, sizeof(crypt_keyfile), "%s%s.%s", 
			KEY_DIR, CRYPT_KEY_FILE, get_my_hostname()); 
    c_stuff = libpbc_init_crypt(crypt_keyfile);

    snprintf(sign_keyfile, sizeof(sign_keyfile), "%s%s", 
			KEY_DIR, CERT_FILE); 
    ctx_plus = libpbc_verify_init(sign_keyfile);

    if( ! (cookie_data = libpbc_unbundle_cookie(cookie, ctx_plus, c_stuff)) )
        return((login_rec *)NULL);

fprintf(stderr, "in verify_login_cookie ready to do bidness\n");

fprintf(stderr, "from l cookie user: %s\n", (*cookie_data).broken.user);
fprintf(stderr, "from l cookie version: %s\n", (*cookie_data).broken.version);
fprintf(stderr, "from l cookie type: %c\n", (*cookie_data).broken.type);
fprintf(stderr, "from l cookie creds: %c\n", (*cookie_data).broken.creds);
fprintf(stderr, "from l cookie serial: %d\n", (*cookie_data).broken.serial);
fprintf(stderr, "from l cookie appsrv_id: %s\n", (*cookie_data).broken.appsrv_id);
fprintf(stderr, "from l cookie app_id: %s\n", (*cookie_data).broken.app_id);
fprintf(stderr, "from l cookie create_ts: %d\n", (int)(*cookie_data).broken.create_ts);
fprintf(stderr, "from l cookie last_ts: %d\n", (int)(*cookie_data).broken.last_ts);

    new->user = (*cookie_data).broken.user;
    new->version = (*cookie_data).broken.version;
    new->type = (*cookie_data).broken.type;
    new->creds = (*cookie_data).broken.creds;
    new->serial = (*cookie_data).broken.serial;
    new->appsrvid = (*cookie_data).broken.appsrv_id;
    new->appid = (*cookie_data).broken.app_id;
    new->create_ts = (*cookie_data).broken.create_ts;
    new->last_ts = (*cookie_data).broken.last_ts;

    return(new);

}

int create_cookie(char *user_buf,
                  char *appsrv_id_buf,
                  char *app_id_buf,
                  char type,
                  char creds,
                  int serial,
                  char *cookie,
 	          int max)
{
    /* special data structs for the crypt stuff */
    md_context_plus 	*ctx_plus;
    crypt_stuff         *c_stuff;
    unsigned char	crypt_keyfile[PBC_1K];
    unsigned char	cert_keyfile[PBC_1K];

    /* measured quantities */
    unsigned char 	user[PBC_USER_LEN];
    unsigned char 	appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char 	app_id[PBC_APP_ID_LEN];

    /* local junk */
    char		*cookie_local;

    /* right size the args */
    strncpy(user, user_buf, sizeof(user));
    user[sizeof(user)-1] = '\0';
    strncpy(appsrv_id, appsrv_id_buf, sizeof(appsrv_id));
    appsrv_id[sizeof(appsrv_id)-1] = '\0';
    strncpy(app_id, app_id_buf, sizeof(app_id));
    appsrv_id[sizeof(app_id)-1] = '\0';

    /* load up the encryption key stuff */
    snprintf(crypt_keyfile, sizeof(crypt_keyfile), "%s%s.%s", 
			KEY_DIR, CRYPT_KEY_FILE, get_my_hostname()); 
    c_stuff = libpbc_init_crypt(crypt_keyfile);

    /* load up the certificate context */
    snprintf(cert_keyfile, sizeof(cert_keyfile), "%s%s", 
			KEY_DIR, CERT_KEY_FILE); 
    ctx_plus = libpbc_sign_init(cert_keyfile);

    /* go get the cookie */
    cookie_local = libpbc_get_cookie(user, type, creds, serial, appsrv_id, app_id, ctx_plus, c_stuff);

    strncpy( cookie, cookie_local, max );
fprintf(stderr, "nice new cookie is: %s\n", cookie);
    return(OK);

}

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*60*10 /* 10 hours */

extern int optind;
extern char *optarg;

krb5_data tgtname = {
    0,
    KRB5_TGS_NAME_SIZE,
    KRB5_TGS_NAME
};

/*
 * Try no preauthentication first; then try the encrypted timestamp
 */
krb5_preauthtype * preauth = NULL;
krb5_preauthtype preauth_list[2] = { 0, -1 };

krb5_context kcontext;
krb5_deltat lifetime = KRB5_DEFAULT_LIFE;       /* -l option */
krb5_timestamp starttime = 0;
krb5_deltat rlife = 0;
int options = KRB5_DEFAULT_OPTIONS;
int option;
int errflg = 0;
krb5_error_code code;
krb5_principal me;
krb5_principal server;
krb5_creds my_creds;
krb5_timestamp now;
krb5_address *null_addr = (krb5_address *)0;
krb5_address **addrs = (krb5_address **)0;
char *client_name, prompt[255];

int auth_kdc(char *username, char *passwd)
{
    int		ret = 1;

    code = krb5_init_context(&kcontext);
    if(code) {
        log_error("auth_kdc: %s while initializing krb5\n", 
			error_message(code));
	abend("can't init krb5 context");
    }

    if((code = krb5_timeofday(kcontext, &now))) {
	log_error("auth_kdc: %s while getting time of day\n", 
			error_message(code));
	abend("can't get the time of day");
    }

    /* just use the name we give you and default domain */
    if ((code = krb5_parse_name (kcontext, username, &me))) {
	 log_error("auth_kdc: ABEND %s when parsing name %s\n", 
			error_message(code), username);
	 abend("krb5 can't parse username");
    }
    
    if ((code = krb5_unparse_name(kcontext, me, &client_name))) {
	log_error("auth_kdc: %s when unparsing name\n", 
			error_message(code));
	abend("misc. krb5 problem");
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    /* me is the pricipal */
    my_creds.client = me;

    /* get server name */
    if((code = krb5_build_principal_ext(kcontext, &server,
			krb5_princ_realm(kcontext, me)->length,
			krb5_princ_realm(kcontext, me)->data,
			tgtname.length, tgtname.data,
			krb5_princ_realm(kcontext, me)->length,
			krb5_princ_realm(kcontext, me)->data,
			0))) {
	log_error("auth_kdc: %s while building server name\n", 
			error_message(code));
	return(FAIL);
    }
	
    my_creds.server = server;

    my_creds.times.starttime = 0;	/* start timer when request
					   gets to KDC */
    my_creds.times.endtime = now + lifetime;

    my_creds.times.renew_till = 0;

    code = krb5_get_in_tkt_with_password(kcontext, options, addrs,
					      NULL, preauth, passwd, 0,
					      &my_creds, 0);
    memset(passwd, 0, sizeof(passwd));
    
    if (code) {
	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	    log_message("auth_kdc: Password incorrect username: %s\n", 
			username);
	else 
	    log_message("auth_kdc: %s while checking credntials username: %s\n",
			error_message(code), username);
	ret = FAIL;
    }

    /* my_creds is pointing at server */
    krb5_free_principal(kcontext, server);

    krb5_free_context(kcontext);
    
    return(ret);
}


#ifdef DEBUG
# define LOGFLAG  0xff
#else
# define LOGFLAG  0x80
#endif

#define TRUE 1
#define FALSE 0

int     test_mode = 0;
