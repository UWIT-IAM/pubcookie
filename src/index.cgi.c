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

    this uses a modified version of the cgic library
    functions that are cgiSomething are from that library
 */

/*
    $Id: index.cgi.c,v 1.7 2000-08-08 00:19:39 willey Exp $
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
#include "securid_securid.h"
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
/* cgic */
#include <cgic.h>

#ifdef MAKE_MIRROR
/* the mirror file is a mirror of what gets written out of the cgi */
/* of course it is overwritten each time this runs                 */
FILE	*mirror;
#endif 

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

#ifdef DEBUG
    fprintf(stderr, "load_login_rec: hello\n");
#endif

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

    l->real_hostname 	= get_string_arg("real_hostname", NO_NEWLINES_FUNC);
    l->appsrv_err 	= get_string_arg("appsrv_err", NO_NEWLINES_FUNC);
    l->file 		= get_string_arg("file", NO_NEWLINES_FUNC);
    l->flag 		= get_string_arg("flag", NO_NEWLINES_FUNC);
    l->referer 		= get_string_arg("referer", NO_NEWLINES_FUNC);

#ifdef DEBUG
    fprintf(stderr, "load_login_rec: bye\n");
#endif

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

/* write a log message via whatever mechanism                                 */
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

void clear_error(const char *service, const char *message) 
{

}

/* send a message to pilot                                                    */
void send_pilot_message(int grade, const char *service, int self_clearing, char *message) 
{

    /* messages sent to pilot */

}

/* logs the message and forwards it on to pilot                               */
/*                                                                            */
/*   args: grade - same grades in pilot, 1 to 5, (5 is lowest)                */
/*         service - a name to id the weblogin service (see note)             */
/*         message - varg message                                             */
/*         self-clearing - does it clear itself (1) or not (0)                */
/*                                                                            */
/*   the trick to services is that there needs to be a TRIGGER event          */
/*      and then a CLEARING event.                                            */
/*                                                                            */
/* Service trigger/clear pairs (keep a log of messages here)                  */
/*   uwnetid-err         uwnetid timeout / o.k. uwnet auth                    */
/*   securid-err         securid timeout / o.k. securid auth                  */
/*   abend               abend / not self-clearing                            */
/*   system-problem      multiple / not self-clearing                         */
/*   version             wrong major version / not self-clearing              */
/*   misc                misc is misc        / not self-clearing              */
/*   auth-kdc            auth_kdc code       / not self-clearing              */
/*   auth-securid        auth securid code   / not self-clearing              */
/*                                                                            */
/*                                                                            */
void log_error(int grade, const char *service, int self_clearing, const char *format,...)
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format), "%s: %s", SYSERR_LOGINSRV_MESSAGE, format);
    vsnprintf(message, sizeof(message), new_format, args);
    log_message(message);
    send_pilot_message(grade, service, self_clearing, message);
    va_end(args);

}

/* when things go wrong and you're not sure what else to do                   */
/* a polite bailing out                                                       */
void abend(char *message) 
{

    log_error(1, "abend", 0, message);
    notok(notok_generic);
    exit(0);

}

#ifdef MAKE_MIRROR
void init_mirror_file() 
{
    mirror = fopen("/tmp/mirror", "w");

}

void close_mirror_file() 
{
    fclose(mirror);

}
#endif 

void print_out(char *format,...)
{
    va_list	args;

    va_start(args, format);
    vprintf(format, args);
    vfprintf(stderr, format, args);
#ifdef MAKE_MIRROR
    vfprintf(mirror, format, args);
#endif 
    va_end(args);

}

char *get_my_hostname() 
{
    struct utsname	myname;

    if ( uname(&myname) < 0 )
        log_error(2, "system-problem", 0, "problem doing uname lookup");

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

/* we've decided not to serialize cookies, but we'll use this field           */
/* for something else in the future                                           */
/* why 23?  consult the stars                                                 */
int get_next_serial()
{
    return(23);

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

#ifdef DEBUG
    fprintf(stderr, "cgiMain: hello\n");
#endif
#ifdef MAKE_MIRROR
    init_mirror_file();
#endif

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

#ifdef DEBUG
    fprintf(stderr, "cgiMain: after get_query\n");
#endif

    /* check the user agent */
    if ( !check_user_agent() ) {
        log_message("bad agent: %s host: %s uri: %s", cgiUserAgent, 
			l->host, l->uri);
        notok(notok_bad_agent);
        exit(0);
    }

#ifdef DEBUG
    fprintf(stderr, "cgiMain: after user agent get_query\n");
#endif

    /* allow for older versions that don't have froce_reauth */
    if ( !l->fr ) {
        l->fr = strdup("NFR");
    }

    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
    /*                                                                   */
    /* the following text should be updated for support for POST         */
    /*                                                                   */
    /* four cases for the main thingie                                   */
    /*   - first time or creds include securid:                          */
    /*         in: no L cookie, bunch of GET data                        */
    /*               OR creds include securid info in g req              */
    /*         out: the login page (includes data from g req)            */
    /*                                                                   */
    /*   - not first time (have L cookie) but L cookie expired or invalid*/
    /*         in: expired or invalid L cookie, g req                    */
    /*         out: the login page (includes data from g req             */
    /*                                                                   */
    /*   - not first time (have L cookie) L cookie not expired and valid */
    /*         in: valid L cookie, g req                                 */
    /*         out: L & G cookies redirect (username comes from L cookie)*/
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
#ifdef DEBUG
        fprintf(stderr, "wohooo!, an answer from the login page!");
#endif
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
    else if( l->creds == PBC_CREDS_UWNETID_SECURID ) {             /* securid */
        log_message("securid implies reauth by %s at %s", l->host, l->appid);
        print_login_page(PRINT_LOGIN_PLEASE, "securid", l->creds, YES_CLEAR_LOGIN);
        exit(0);
    }
    else if ( !has_login_cookie() ) {          /* no l cookie, must login */
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

#ifdef MAKE_MIRROR
    close_mirror_file();
#endif

    return(0);  
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
        strcpy(input_type2, "PASSWORD");
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

#ifdef DEBUG
    fprintf(stderr, "check_login_uwnetid: hello\n");
#endif 

    if( auth_kdc(user, pass) == OK ) {
        clear_error("uwnetid-fail", "securid auth ok");
        return(CHECK_LOGIN_RET_SUCCESS);
    }
    else {
        log_error(2, "uwnetid-err", 1, "problem doing uwnetid auth");
        return(CHECK_LOGIN_RET_FAIL);
    }

}

char *check_login_securid(char *user, char *sid, login_rec *l)
{
    if( auth_securid(user, sid, l) == OK ) {
        clear_error("securid-fail", "uwnetid auth ok");
        return(CHECK_LOGIN_RET_SUCCESS);
    }
    else {
        log_error(2, "securid-err", 1, "problem doing securid auth");
        return(CHECK_LOGIN_RET_FAIL);
    }

}

/* successful auth returns CHECK_LOGIN_RET_SUCCESS                            */
char *check_login(login_rec *l)
{
    char	*ret;

#ifdef DEBUG
    fprintf(stderr, "in check_login\n");
#endif

    if( !(ret = malloc(100)) ) {
        abend("out of memory");
    }

    strcpy(ret, CHECK_LOGIN_RET_BAD_CREDS);

    if( l->creds == PBC_CREDS_UWNETID ) {
        strcpy(ret, check_login_uwnetid(l->user, l->pass));
    }
    else if( l->creds == PBC_CREDS_UWNETID_SECURID ) {
        strcpy(ret, check_login_securid(l->user, l->pass2, l));
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

#ifdef DEBUG
    fprintf(stderr, "check_l_cookie: hello\n");
#endif

    if( !(cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }

    /* get the login request cookie */
    if( !get_cookie(PBC_L_COOKIENAME, cookie, PBC_4K-1) ) {
        abend("no login cookies");
        return 0;
    }

    /* $verify_pgm takes arguments on the command line         */
    /* the arguments are <cookie type> <crypt key> <cert file> */
    /* and the cookie on stdin, it returns the information     */
    /* from teh cookie on stdout                               */

    lc = verify_login_cookie(cookie, l);

    if( !lc ) {
        log_message("couldn't deal with cookie %s", cookie);
        return("couldn't decode login cookie");
    }

#ifdef DEBUG
    fprintf(stderr, "in check_l_cookie ready to look at cookie contents %s\n", lc->user);
#endif

    /* look at what we got back from the cookie */
    if( ! lc->user ) {
        log_error(5, "system-problem", 0, "no user from L cookie? user from g_req: %s", l->user);
        return "malformed";
    }

    if( (lc->create_ts + EXPIRE_LOGIN) < (t=time(NULL)) ) {
        log_message("expired login cookie: created: %d timeout: %dsecs now: %d",
			lc->create_ts, EXPIRE_LOGIN, t);
        return "expired";
    }

#ifdef DEBUG
    fprintf(stderr, "in check_l_cookie ready to look at cookie creds %c\n", lc->creds);
#endif

    if( lc->creds != l->creds ) {
        if( l->creds == PBC_CREDS_UWNETID ) {
            if( lc->creds != PBC_CREDS_UWNETID_SECURID ) {
                log_message("wrong_creds: from login cookie: %s from request: %s", lc->creds, l->creds);
                return("wrong_creds");
            }
        }
        else {
            log_message("wrong_creds: from login cookie: %s from request: %s", lc->creds, l->creds);
            return("wrong_creds");
        }
    }

    l_version = lc->version; g_version = l->version;
    if( *l_version != *g_version ) {
        log_error(5, "version", 0, "wrong major version: from L cookie %s, from g_req %s for host %s", l_version, g_version, l->host);
        return("wrong major version");
    }
    if( *(l_version+1) != *(g_version+1) ) {
        log_message("warn: wrong minor version: from l cookie %s, from g_req %s for host %s", l_version, g_version, l->host);
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

    print_out("<INPUT TYPE=\"hidden\" NAME=\"real_hostname\" VALUE=\"%s\">\n",
		(l->real_hostname ? l->real_hostname : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"appsrv_err\" VALUE=\"%s\">\n",
		(l->appsrv_err ? l->appsrv_err : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"file\" VALUE=\"%s\">\n",
		(l->file ? l->file : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"flag\" VALUE=\"%s\">\n",
		(l->flag ? l->flag : "") );
    print_out("<INPUT TYPE=\"hidden\" NAME=\"referer\" VALUE=\"%s\">\n",
		(l->referer ? l->referer : "") );

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
        log_error(2, "system-problem", 0, "can't open ok browsers file: %s, continuing", OK_BROWSERS_FILE);
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
    int			serial = 0;
    char		*g_cookie;
    char		*l_cookie;
    char		*redirect_uri;
    char		*message;
    char		*redirect_dest = NULL;
    char		g_set_cookie[PBC_1K];
    char		l_set_cookie[PBC_1K];
    char		clear_g_req_cookie[PBC_1K];
    int			g_res, l_res;
    int			limitations_mentioned = 0;
    char		*submit_value = NULL;
    cgiFormEntry 	*c = cgiFormEntryFirst;
    cgiFormEntry 	*n;

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

    /* if we have a problem then bail with a nice message */
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
          log_error(1, "system-problem", 0, "Not able to create cookie for user %s at %s-%s", l->user, l->appsrvid, l->appid);
          free(message);
          return;
    }

fprintf(stderr, "in print_redirect_page cookies are ok\n");

    /* create the http header line with the cookie */
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
		PBC_G_REQ_COOKIENAME,
		EARLIEST_EVER);


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

fprintf(stderr, "about to base64_decode: %s\n", l->args);
        args_enc = strdup(l->args);    
	base64_decode(l->args, args_enc);
fprintf(stderr, "and they are: %s\n", args_enc);
        snprintf( redirect_dest, PBC_4K, "%s?%s", redirect_dest, args_enc );
    }

    log_message ("about to do redirect of %s for host %s, redirect is: %s", 
				l->user, l->host, redirect_dest);

    /* now blat out the redirect page */
    print_out("%s\n", g_set_cookie);
    print_out("%s\n", l_set_cookie);
    print_out("%s\n", clear_g_req_cookie);

    /* incase we have a post */
    if ( l->post_stuff ) {
        /* cgiParseFormInput will extract the arguments from the post */
        /* make them available to subsequent cgic calls */
        if( cgiParseFormInput(l->post_stuff, strlen(l->post_stuff))
                   != cgiParseSuccess ) {
            log_error(5, "misc", 0, "couldn't parse the decoded granting request cookie");
            notok(notok_generic);
            exit(0);
        }

        print_out("Pragma: No-Cache\n");
        print_out("Content-Type: text/html\n\n\n");
	print_out("<HTML>");
	/* when the page loads click on the last element */
        /* (which will always be the submit) in the array */
        /* of elements in the first, and only, form. */
	print_out("<BODY BGCOLOR=\"white\" onLoad=\"document.forms[0].elements[document.forms[0].elements.length-1].click()\">\n");
	print_out("<CENTER>");
        print_table_start();
	print_out("<TR><TD ALIGN=\"LEFT\">\n");

	print_out("<FORM METHOD=\"POST\" ACTION=\"$redirect_dest\" ");
        print_out("ENCTYPE=\"application/x-www-form-urlencoded\" ");
        print_out("NAME=\"query\">\n");

        while (c) {
            // in the perl version we had to make sure we were getting
            // rid of this header line
            //        c->attr =~ s%^\s*HTTP/1.1 100 Continue\s*%%mi;

            /* if there is a " in the value string we have to put */
            /* in a TEXTAREA object that will be visible          */
            if( strstr(c->value, "\"") ) {
                if( ! limitations_mentioned ) {
                    print_out("Certain limitations require that this be shown, please ignore it<BR>\n");
                    limitations_mentioned++;
                }
                print_out("<TEXTAREA COLS=0 ROWS=0 NAME=\"%s\">\n", c->attr);
                print_out("%s</TEXTAREA>", c->value);
                print_out("<P>\n");
            }
            else {
                /* we don't want to cover other people's submits */
                if ( !strcmp(c->attr, "submit") )  {
                    submit_value = c->value;
                }
                else {
                    print_out("<INPUT TYPE=\"hidden\" ");
		    print_out("NAME=\"%s\" VALUE='%s'>\n", c->attr, c->value);
                }
    	    }

            /* move onto the next attr/value pair */
            n = c->next;
            c = n;
        } /* while c */


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
    } /* end if post_stuff */

    free(g_cookie);
    free(l_cookie);
    free(message);
    free(redirect_dest);
fprintf(stderr, "leaving print_redirect_page\n");

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
            log_message("no granting request cookie");
            notok(notok_generic);
            return(NULL);
        }
        g_req_clear = decode_granting_request(g_req);

// ssw debug
fprintf(stderr, "this is the decoded greg %s\n", g_req_clear);

        if( cgiParseFormInput(g_req_clear, strlen(g_req_clear)) 
                   != cgiParseSuccess ) {
            log_error(5, "misc", 0, "couldn't parse the decoded granting request cookie");
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

int auth_kdc(char *username, char *passwd)
{

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
krb5_context kcontext;
krb5_deltat lifetime = KRB5_DEFAULT_LIFE;       /* -l option */
int options = KRB5_DEFAULT_OPTIONS;
krb5_error_code code;
krb5_principal me;
krb5_principal kserver;
krb5_creds my_creds;
krb5_timestamp now;
krb5_address **addrs = (krb5_address **)0;
char *client_name;

    int		ret = 1;

    code = krb5_init_context(&kcontext);
    if(code) {
        log_error(2, "auth-kdc", 1, "auth_kdc: %s while initializing krb5\n", 
			error_message(code));
	abend("can't init krb5 context");
    }

    if((code = krb5_timeofday(kcontext, &now))) {
	log_error(2, "auth-kdc", 1, "auth_kdc: %s while getting time of day\n", 
			error_message(code));
	abend("can't get the time of day");
    }

    /* just use the name we give you and default domain */
    if ((code = krb5_parse_name (kcontext, username, &me))) {
	 log_error(2, "auth-kdc", 1, "auth_kdc: ABEND %s when parsing name %s\n", 
			error_message(code), username);
	 abend("krb5 can't parse username");
    }
    
    if ((code = krb5_unparse_name(kcontext, me, &client_name))) {
	log_error(2, "auth-kdc", 1, "auth_kdc: %s when unparsing name\n", 
			error_message(code));
	abend("misc. krb5 problem");
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    /* me is the pricipal */
    my_creds.client = me;

    /* get kserver name */
    if((code = krb5_build_principal_ext(kcontext, &kserver,
                        krb5_princ_realm(kcontext, me)->length,
                        krb5_princ_realm(kcontext, me)->data,
                        tgtname.length, tgtname.data,
                        krb5_princ_realm(kcontext, me)->length,
                        krb5_princ_realm(kcontext, me)->data,
                        0))) {
	log_error(2, "auth-kdc", 1, "auth_kdc: %s while building kserver name\n", 
			error_message(code));
	return(FAIL);
    }
	
    my_creds.server = kserver;

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
    krb5_free_principal(kcontext, kserver);

    krb5_free_context(kcontext);
    
    clear_error("auth-kdc", "auth_kdc ok");

    return(ret);

}


/* all of the securid stuff is in files name securid_                         */
int auth_securid(char *username, char *sid, login_rec *l) 
{
    int		ret;

    /* securid and next prn */
    if( (ret=securid(username, sid) == -1) ) {
         print_login_page("Next SecurID PRN", "next PRN", l->creds, NO_CLEAR_LOGIN);
    } 
    else if( ret == 0 ) {
        return(OK);
    }

    return(FAIL);

}
