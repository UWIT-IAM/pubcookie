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
    $Id: index.cgi.c,v 1.2 1999-10-21 01:29:13 willey Exp $
 */


/* LibC */
#include <netdb.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* openssl */
#include <pem.h>
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
/* cgic */
#include <cgic.h>

 /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*                                                                         */
 /* the following text should be updated for support for POST               */
 /*                                                                         */
 /* four cases for the main thingie                                         */
 /*   - first time or force_reauth:                                         */
 /*         in: no L cookie, bunch of GET data                              */
 /*               OR force_reauth info in GET                               */
 /*         out: the login page (includes data from get)                    */
 /*                                                                         */
 /*   - not first time (have L cookie) but L cookie expired or invalid      */
 /*         in: expired or invalid L cookie, bunch of GET data              */
 /*         out: the login page (includes data from get)                    */
 /*                                                                         */
 /*   - not first time (have L cookie) L cookie not expired and valid       */
 /*         in: valid L cookie, bunch of GET data                           */
 /*         out: L & G cookies redirect (username comes from cookie)        */
 /*                                                                         */
 /*   - POST from login page                                                */
 /*         in: POST data that include creds                                */
 /*         process: validate creds                                         */
 /*         out: if successful L & G cookies redirect else login page       */
 /*                                                                         */
 /* the above text should be updated for support for POST                   */
 /*                                                                         */
 /*                                                                         */
 /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 





  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*	general utility thingies                                            */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

char *get_string_arg(char *name, cgiFormResultType (*f)())
{
    int		length;
    char	*s;

    cgiFormStringSpaceNeeded(name, &length);
    s = calloc(length, sizeof(char));

    switch( (int)f(s, length) ) {
    case cgiFormSuccess:
        return(s);
        break;
    case cgiFormNotFound:
        log_message("empty string when looking for argument %s in query string", name);
        return(NULL);
        break;
    case cgiFormTruncated:
        log_error("truncated string when looking for argument %s in query string", name);
        return(s);
        break;
    default:
        return(s);
        break;
    }

}

char *url_encode(char *in)
{
    return(in);

}

void log_message(const char *format,...) 
{
    va_list	args;
    char	new_format[PBC_4K];

    va_start(args, format);
    snprintf(new_format, strlen(new_format)+1, "%s: %s", ANY_LOGINSRV_MESSAGE, format);
    libpbc_debug(new_format, args);
    va_end(args);
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
    snprintf(new_format, strlen(new_format)+1, "%s: %s", SYSERR_LOGINSRV_MESSAGE, format);
    vsnprintf(message, strlen(message)+1, new_format, args);
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
            in = p;
        else
            word_start = 1;

        /* no spaces at the end */
        if(*p == ' ' && word_start)
            *p = '\0';

        p++;
    }
 
    return(in);

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
    if( !getenv("HTTPS") || !strcmp( getenv("HTTPS"), "on" ) ) { 
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

    /* check the user agent */
    if ( !check_user_agent() ) {
        log_message("bad agent: %s host: %s uri: %s", getenv("HTTP_USER_AGENT"), l->host, l->uri);
        notok(notok_bad_agent);
        exit(0);
    }

    /* allow for older versions that don't have froce_reauth */
    if ( !l->fr ) {
        l->fr = strdup("NFR");
    }

    /* the main logic (see first comment block) */
    if ( l->user ) {          /* a reply from the login page */
        if( !(res = check_login(l)) ) {
            log_message("Authentication failed: %s type: %d %s", l->user, l->creds, res);
            if( !strcmp(res, "Authentication Failed") ) {
                snprintf(message, strlen(message)+1, "%s%s%s<P>%s",
                    PBC_EM1_START,
                    AUTH_FAILED_MESSAGE1,
                    PBC_EM1_END, 
                    AUTH_FAILED_MESSAGE2);
            }
            else {
                log_error("Login problem: %s", res);
                snprintf(message, strlen(message)+1, "%s%s%s<P>%s",
                    PBC_EM1_START,
                    AUTH_TROUBLE,
                    PBC_EM1_END);
            }
            print_login_page(message, "bad auth", l->creds, NO_CLEAR_LOGIN);
            exit(0);
        }
        log_message("Authentication success: %s type: %d", l->user, l->creds);
    }
    else if( !strcmp(l->fr,"NFR") ) {               /* force reauth */
        log_message("user was forced to reauth by %s at %s", l->host, l->appid);
        print_login_page(PRINT_LOGIN_PLEASE, "force reauth", l->creds, YES_CLEAR_LOGIN);
        exit(0);
    }
    else if ( !has_login_cookie ) {                 /* no l cookie */
        print_login_page(PRINT_LOGIN_PLEASE, "no L cookie yet", l->creds, NO_CLEAR_LOGIN);
        exit(0);
    }
    else if ( (res=check_l_cookie(l)) ) {        /* problem w/ the l cookie*/
        log_message("Login cookie bad: %s", res);
        print_login_page(PRINT_LOGIN_PLEASE, res, l->creds, YES_CLEAR_LOGIN);
        exit(0);
    }

    /* the reward for a hard days work                                        */
    log_message("Issuing cookies for $user at $ENV{REMOTE_ADDR} on $host at $appid");

    /* generate the cookies and print the redirect page                       */
    print_redirect_page(l);

//    exit(1);
    return(1);
}


void print_login_page(char *message, char *reason, int creds, int need_clear_login)
{
    char	*word;
    char	*field_label1;
    char	*field_label2;
    char	*hostname = strdup(get_domain_hostname());

    switch (creds) {
    case 1:
        field_label1 = strdup(PROMPT_UWNETID);
        word = strdup("password");
        break;
    case 2:
        field_label1 = strdup("Invalid request\n");
        word = strdup("INVALID REQUEST");
        break;
    case 3:
        field_label2 = strdup(PROMPT_SECURID);
        field_label1 = strdup(PROMPT_UWNETID);
        word = strdup("password and SecurID");
        break;
    default:
        field_label1 = strdup(PROMPT_UWNETID);
        word = strdup("password");
        break;
    }

    print_out("Content-Type: text/html\n");
    if( need_clear_login ) 
        print_out("Set-Cookie: %s=clear; domain=%s; path=%s; expires=Fri, 11-Jan-1990 00:00:01 GMT; secure\n", PBC_L_COOKIENAME, hostname, LOGIN_DIR);
    print_out("\n\n");

    print_login_page_part1(YES_FOCUS);

    print_out("<P>%s</P>\n", message);
    print_out("<!-- -- %s -- -->\n", reason);
//
//    # if everything is cool then give this nice text
//    if ( $message eq $print_login_please ) {
//        print_login_page_part2a();
//    }
//    print_login_page_part2b();
//
//    /* seperate from above since this is where the form is */
//    print_login_page_part3($word);
//
//    print $field_label;
//    print "<INPUT TYPE=\"";
//    if ( $field_label eq $prompt_uwnetid ) {
//        print "PASSWORD";
//    }
//    print "\" NAME=\"pass\" SIZE=\"20\">\n<P>\n";
//        
//    if ( $field_label2 eq $prompt_uwnetid ) {
//        print $field_label2;
//        print "<INPUT TYPE=\"";
//        print "PASSWORD\" NAME=\"pass2\" SIZE=\"20\">\n";
//    }
//    elsif ( $field_label2 eq $prompt_securid ) {
//        print $field_label2;
//        print "<INPUT TYPE=\"";
//        print "TEXT\" NAME=\"pass2\" SIZE=\"20\">\n";
//    }
//
//    &print_login_page_part4;
//
//    &print_login_page_part_expire_info;
//
//    &print_login_page_part5;
//
}
//
//
/* this is where we check the auth info                                       */
/*     authsrv calls are meta-auth                                            */
/* successful auth returns NULL                                               */
char *check_login(login_rec *l)
{
//    my $ret = "invalid creds";
//
//    if ( $creds eq "1" ) {
//        $ret = check_login_uwnetid($user, $pass);
//    }
//    elsif ( $creds eq "3" ) {
//        if ( ($ret = check_login_securid($user, $pass2)) eq "success" ) {
//            $ret = check_login_uwnetid($user, $pass);
//        }
//        else {
//            return $ret;
//        }
//    }
//
    return((char *)NULL);

}


//
//sub check_login_uwnetid {
//    my ($user, $pass) = @_;
//    my $result;
//
//    if ( authsrv::authenticate(\$result, 10, $$, 'auth-only', 0, 0,
//                                        [ 'uapasswd' ],
//                                        {
//                                            'username' => $user,
//                                            'uapasswd' => $pass
//                                        }) ) {
//        $main::user = $user;
//        return "success";
//    }
//    else {
//        return $result . " uwnetid";    
//    }
//
//}
//
//sub check_login_securid {
//    my ($user, $pass) = @_;
//    my $result;
//
//    if ( authsrv::authenticate(\$result, 10, $$, 'auth-only', 0, 0,
//                                        [ 'securid' ],
//                                        {
//                                            'username' => $user,
//                                            'sid' => $pass
//                                        }) ) {
//        $main::user = $user;
//        return "success";
//    }
//    else {
//        return $result . " securid";    
//    }
//
//}
//
//
/* returns NULL if o.k.                                                       */
/*   else a description of the failure                                        */
char *check_l_cookie(login_rec *l)
{
//    my ($c_user, $c_version, $c_type, $c_creds, $c_appsrv_id, $c_app_id, $c_create_ts, $c_last_ts);
//    my $wtr = gensym;
//    my $rdr = gensym;
//    my $err = gensym;
//
//    # get the login request cookie(s)
//    my @cookies = get_cookie_fromenv(&PBC_L_COOKIENAME);
//
//    # maybe deny them if they have muliple login request cookies
//    # for now just log it.
//    if ( scalar @cookies > 1 ) {
//        log_error("MULTIPLE login request cookies? for $ENV{'REQUEST_URI'}");
//    }
//    elsif ( scalar @cookies == 0 ) {
//        log_message("FAIL zero login cookies? for $ENV{'REQUEST_URI'}");
//        return 0;
//    }
//
//    my $login_cookie = $cookies[-1];
//
//    # $verify_pgm takes arguments on the command line
//    # the arguments are <cookie type> <crypt key> <cert file>
//    # and the cookie on stdin, it returns the information 
//    # from teh cookie on stdout
//
//    my $cmd = "$verify_pgm 3 $crypt_key $cert_file";
//# extra debugging
//#    log_message ("check_l_cookie: about to do verify: $cmd");
//
//    if( ! open3($wtr, $rdr, $err, $cmd) ) {
//        log_error ("check_l_cookie: open3 of cmd $cmd failed $!");
//        return "system_problem";
//    }
//    print $wtr $login_cookie;
//    close $wtr;
//    while(<$rdr>) {
//        chomp;
//        $c_user = $1 if ( /user: (.*)(\s|$)/ );
//        $c_version = $1 if ( /version: (.*)(\s|$)/ );
//        $c_type = $1 if ( /type: (.)/ );
//        $c_creds = $1 if ( /creds: (.)/ );
//        $c_appsrv_id = $1 if ( /appsrv_id: (.*)(\s|$)/ );
//        $c_app_id = $1 if ( /app_id: (.*)(\s|$)/ );
//        $c_create_ts = $1 if ( /create_ts: (\d+)(\s|$)/ );
//        $c_last_ts = $1 if ( /last_ts: (\d+)(\s|$)/ );
//    }
//    close $rdr;
//    while(<$err>) {
//        log_error("check_l_cookie: error doing verify: $_");
//    }
//    close $err;
//
//    # look at what we got back from the cookie
//    if ( ! $c_user ) {
//        log_error("no user from login cookie?: $user");
//        return "malformed";
//    }
//    my $t;
//    if ( ($c_create_ts + $expire_login) < ($t=time) ) {
//        log_message("expired login cookie: created: $c_create_ts timeout: $expire_login seconds now: $t");
//        return "expired";
//    }
//
//    if ( $c_creds ne $creds ) {
//        if ( $creds eq "1" ) {
//            if ( $c_creds ne "3" ) {
//                return "wrong_creds: from login cookie: $c_creds from request: $creds";
//            }
//        }
//        else {
//            return "wrong_creds: from login cookie: $c_creds from request: $creds";
//        }
//    }
//
//    # check version
//    if ( substr($c_version, 0, 1) ne substr($version, 0, 1) ) {
//        log_message ("wrong major version: from login cookie $c_version, from granting request $version");
//        return "wrong_version";
//    }
//    if ( substr($c_version, 1, 1) ne substr($version, 1, 1) ) {
//        log_message("WARNING: wrong minor version: from login cookie $c_version, from granting request $version, for host $host, it's ok for now");
//    }
//
//    # make sure it's a login cookie
//    if ( $c_type ne '3' ) {
//        return "malformed";
//    }
//
//    $user = $c_user;
//    $creds = $c_creds;
    return((char *)NULL);
}



//
char *get_cookie_created(char *line)
{
//    my($line) = @_;
//    my $ret;
//    my $wtr = gensym;
//    my $rdr = gensym;
//    my $err = gensym;
//
//# extra debugging
//#    log_message ("get_cookie_created: about to pipe $line to $create_pgm");
//    if( ! open3($wtr, $rdr, $err, $create_pgm) ) {
//        log_error("get_cookie_created: open3 of cmd $create_pgm FAILED $!");
//        return "";
//    }
//    print $wtr $line;
//    close $wtr;
//    while(<$err>) {
//        log_error("get_cookie_created: error doing create: $_");
//    }
//    $ret = <$rdr>;
//    close $rdr; close $err;
    return line;
}
//
//sub url_encode {
//    my ($in) = @_;
//    my $out = $in;
//    $out =~ s/"/%22/g;
//    $out =~ s/%/%25/g;
//    $out =~ s/&/%26/g;
//    $out =~ s/\+/%2B/g;
//    $out =~ s/:/%3A/g;
//    $out =~ s/;/%3B/g;
//    $out =~ s/=/%3D/g;
//    $out =~ s/\?/%3F/g;
//    $out =~ s/ /+/g;
//    return $out;
//}
//
//sub warn_old_module_version {
//    my ($host, $version, $notes) = @_;
//
//    log_message ("WARNING old module version running on $host: version: $version why i know: $notes");
//}
//
//sub get_next_serial {
//    return 1;
//}
//
//sub untaint {
//    my ( $v ) = shift;
//    $v =~ /^(.*)$/;
//    return $1;
//}
//
//sub decode_g_req_cookie {
//    
//    # get the granting request cookie(s)
//    my @g_req_cookie = get_cookie_fromenv(&PBC_G_REQ_COOKIENAME);
//
//    # maybe deny them if they have muliple granting request cookies
//    # for now just log it.
//    if ( scalar @g_req_cookie > 1 ) {
//        log_error("MULTIPLE granting request cookies? for $ENV{'REQUEST_URI'}");
//    }
//    elsif ( scalar @g_req_cookie == 0 ) {
//        return 0;
//    }
//
//    # if there are multiple use the last one
//    my $arg_line = decode_base64($g_req_cookie[-1]);
//
//    # once unencoded the granting req are just cgi arguments
//    # and can be treated as such
//    my $g_req_args = new CGI($arg_line);
//    $g_req_args->import_names('QS');
//
//    $args = $QS::eight;		
//    $uri = $QS::seven;
//    $host = $QS::six;
//    $method = $QS::five;
//    $version = $QS::four;
//    $creds = $QS::three;
//    $appid = $QS::two;
//    $appsrvid = $QS::one;
//    $fr = $QS::fr;
//
//    # incase we have a post
//    my $g_req_args = new CGI;
//    $g_req_args->import_names('QP');
//    $post_stuff = $QP::post_stuff;
//
//}
//
//# this allows for multiple cookies of the same name
//# is that a good thing?
//sub get_cookie_fromenv {
//    my ($name) = @_;
//    my $i = -1;
//    my @cookies;
//
//    $name .= "=";
//    my $c_string = $ENV{'HTTP_COOKIE'};
//
//    while ( (i=index(c_string, name, i+1)) != -1 ) {
//        end = index(c_string, ";", i);
//        end = ( end == -1 ) ? length(c_string) : end;
//	  my len = end - i - length(name);
//        push( @cookies, substr(c_string, i+length(name), len) );
//    }
//
//    return @cookies;
//}
//
//
//
//
//################################### print_problem 3
//sub print_problem3 {
//
//    print <<"EOS";
//
//<P><B><font size="+1" color="#FF0000">This browser doesn't accept cookies!</font></B></P>
//
//<p><b><font size="+1">Your browser must <a href="http://www.washington.edu/computing/web/cookies.html">accept cookies</a> in
//order to use the UW NetID login page.</font></b></p>
//
//<p>&nbsp;</p>
//
//EOS
//}
//


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
}

void notok_bad_agent() 
{
    print_out("%s", NOTOK_BAD_AGENT_TEXT1);

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
    print_out("Content-Type: text/html\n","");

    /* if we got a form multipart cookie, reset it */
    if ( getenv("HTTP_COOKIE") && strstr(getenv("HTTP_COOKIE"), PBC_FORM_MP_COOKIENAME) ) {
        print_out("Set-Cookie: %s=done; domain=.washington.edu; path=/; expires=Fri, 11-Jan-1990 00:00:01 GMT", PBC_FORM_MP_COOKIENAME);
    }

    print_out("\n\n","");

    print_login_page_part1(NO_FOCUS);

    notok_f();

    print_login_page_part5();

}


int cookie_test() 
{
    char        *cookies;

    if ( !(cookies = calloc( strlen(getenv("HTTP_COOKIE"))+1, sizeof(char) )) ){
        notok(notok_no_g_or_l);
        return(0);
    }
    
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

    if ( focus ) {
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
    print_out("<TD WIDTH=2 BGCOLOR=\"#000000\"><IMG SRC=\"/images/1pixffcc33iystpiwfy.gif\" WIDTH=\"1\" HEIGHT=\"1\" ALIGN=\"BOTTOM\" ALT=\"\"></TD>\n\n");
    print_out("<TD WIDTH=9>&nbsp;</TD>\n\n");
    print_out("<TD WIDTH=200 VALIGN=\"MIDDLE\">\n");
    print_out("<FORM METHOD=\"POST\" ACTION=\"/\" ENCTYPE=\"application/x-www-form-urlencoded\" NAME=\"query\">\n");
    print_out("<p>Enter your UW NetID and %s below, then click the Login button.</p>\n", word);
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
    print_out("<INPUT TYPE=\"hidden\" NAME=\"one\" VALUE=\"%s\">\n", l->appsrvid);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"two\" VALUE=\"%s\">\n", l->appid);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"three\" VALUE=\"%s\">\n", l->creds);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"four\" VALUE=\"%s\">\n", l->version);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"five\" VALUE=\"%s\">\n", l->method);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"six\" VALUE=\"%s\">\n", l->host);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"seven\" VALUE=\"%s\">\n", l->uri);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"eight\" VALUE=\"%s\">\n", l->args);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"fr\" VALUE=\"%s\">\n", l->fr);
    print_out("<INPUT TYPE=\"hidden\" NAME=\"post_stuff\" VALUE=\"%s\">\n", l->post_stuff);
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

int check_user_agent()
{
    char        *agent;
    char        line[PBC_4K];
    FILE	*ifp;

    if ( !(agent = calloc( strlen(getenv("HTTP_USER_AGENT"))+1, sizeof(char) )) ){
        /* what does it mean if HTTP_USER_AGENT isn't set? */
        log_error("a request without a user agent?");
        return(1);
    }
    
    if ( !(ifp = fopen(OK_BROWSERS_FILE, "r")) ) {
        log_error("can't open ok browsers file: %s, continuing", OK_BROWSERS_FILE);
        return(1);
    }

    while( fgets(line, strlen(line),ifp ) ) {
        if( line[0] == '#' )
            continue;
        if( strstr( agent, line ) )
            return(1);
    }

    return(0);

}


void print_redirect_page(login_rec *l)
{
    int		serial = 0;
    char	create_l_line[PBC_1K];
    char	create_g_line[PBC_1K];
    char	*submit_value;
    char	*g_cookie;
    char	*l_cookie;
    char	*message;
    char	*redirect_dest;

    serial = get_next_serial();

    /* setup to make the granting and login cookies  */
    snprintf(create_l_line, strlen(create_l_line)+1, "%s %s %s %s %d %d %s%s %s%s",
    		url_encode(l->user),
                url_encode(l->appsrvid),
                url_encode(l->appid),
                PBC_COOKIE_TYPE_L,
                l->creds,
                serial,
                KEY_DIR,
                CRYPT_KEY_FILE,
                KEY_DIR,
                CERT_KEY_FILE);

    snprintf(create_g_line, strlen(create_g_line)+1, "%s %s %s %s %d %d %s%s %s%s",
    		url_encode(l->user),
                url_encode(l->appsrvid),
                url_encode(l->appid),
                PBC_COOKIE_TYPE_G,
                l->creds,
                serial,
                KEY_DIR,
                CRYPT_KEY_FILE,
                KEY_DIR,
                CERT_KEY_FILE);

    /* cook up them cookies */
    if ( !(l_cookie = get_cookie_created(create_l_line)) ||
         !(g_cookie = get_cookie_created(create_g_line)) ) {

          snprintf( message, strlen(message)+1, "%s%s%s%s%s%s",
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
          return;
    }

//my $g_set_cookie = "Set-Cookie: pubcookie_g=$g_cookie; domain=.washington.edu; path=/; secure";
//my $s_set_cookie = "Set-Cookie: pubcookie_l=$l_cookie; domain=$hostname; path=$login_dir; secure";
//my $clear_g_req_cookie = "Set-Cookie: " . &PBC_G_REQ_COOKIENAME . "=done; domain=.washington.edu; path=/; expires=Fri, 11-Jan-1990 00:00:01 GMT";
//
//
//# whip up the url to send the browser back to
//my $redirect_uri;
//if ( $fr eq "NFR" || $fr eq "" ) {
//    $redirect_uri = $uri;
//}
//else {
//    if ( $fr =~ /^\// ) {
//        $redirect_uri = $fr;
//    } 
//    else {
//        $redirect_uri = "/" . $fr;
//    } 
//}
//
//my $redirect_dest = "https://". $host . $redirect_uri;
//if ( $args ) {
//    $redirect_dest .= "?" . decode_base64($args);
//}
//
//# extra debugging
//log_message ("main: about to do redirect of $user for host $host, redirect is: $redirect_dest");
//
//# now blat out the redirect page
//print $g_set_cookie, "\n";
//print $s_set_cookie, "\n";
//print $clear_g_req_cookie, "\n";
//
    if ( l->post_stuff ) {
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

}


login_rec *get_query() 
{
    login_rec		*l = malloc(sizeof(login_rec));

    l->args 		= get_string_arg("eight", YES_NEWLINES);
    l->uri 		= get_string_arg("seven", NO_NEWLINES);
    l->method 		= get_string_arg("five", NO_NEWLINES);
    l->version 		= get_string_arg("four", NO_NEWLINES);
//    l->creds 		= get_string_arg("three", NO_NEWLINES);
    l->appid 		= get_string_arg("two", NO_NEWLINES);
    l->appsrvid 	= get_string_arg("one", NO_NEWLINES);
    l->fr 		= get_string_arg("fr", NO_NEWLINES);

    l->user 		= get_string_arg("user", NO_NEWLINES);
    l->user 		= clean_username(l->user);
    l->pass 		= get_string_arg("pass", NO_NEWLINES);
    l->pass2 		= get_string_arg("pass2", NO_NEWLINES);
    l->post_stuff	= get_string_arg("post_stuff", YES_NEWLINES);

//    &decode_g_req_cookie;

    return(l);
}



