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
    $Id: index.cgi.c,v 1.1 1999-10-16 00:50:44 willey Exp $
 */


//#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
//#include <pem.h>
//#include <unistd.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//##include <arpa/inet.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"

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




//
//# some setting for the cookies and redirect
//my $login_dir = "/";
//my $refresh = "0";
//my $expire_login = 60 * 60 * 8;
//
//my $notok_needssl = "I'm sorry this page is only accessible via a SSL protected connection. <BR>\n";
//
//# some messages about people who hit POSTS and don't have js on
//my $pbc_post_no_js_text = "Thank you for logging on\n";
//my $pbc_post_no_js_button = "Click here to continue\n";
//
//my $print_login_please = "Please log in.";
//my $trouble_creating_cookie = "Trouble creating cookie, please re-enter.";
//my $problems_persist = "If problems persist contact help\@cac.washington.edu.";
//my $auth_failed_message1 = "Login failed. Please re-enter.";
//my $auth_failed_message2 = "Please make sure:<BR><UL><LI>Your Caps Lock key is OFF.<LI>Your Number Lock key is ON.</UL>";
//
//my $prompt_uwnetid = "<B>Password:</B><BR>\n";
//my $prompt_securid = "<B>SecurID:</B><BR>\n";
//
//# how we accentuate WARNING messages
//my $pbc_em1_start = "<B><font color=\"#FF0000\" size=\"+1\">"; 
//my $pbc_em1_end = "</font></B><BR>";
//# how we accentuate less important WARNING messages
//my $pbc_em2_start = "<B><font size=\"+1\">"; 
//my $pbc_em2_end = "</font></B><BR>";
//
//# keys and certs
//my $key_dir = "/usr/local/pubcookie/";
//my $crypt_key = $key_dir . "c_key." . $host;
//my $cert_file = $key_dir . "pubcookie.cert";
//my $cert_key_file = $key_dir . "pubcookie.key";
//
//# programs for creating and verifying cookies
//my $create_pgm = "/usr/local/pubcookie/pbc_create";
//my $verify_pgm = "/usr/local/pubcookie/pbc_verify";
//
//# some misc settings
//my $serial_file = "/tmp/s";
//my $first_serial = 23;
//
//# file to get the list of ok browsers from
//my $ok_browsers_file = "/usr/local/pubcookie/ok_browsers";
//
//# utility to send messages to pilot
//my $send_pilot_cmd = "/usr/local/adm/send_pilot_stat.pl";
//
//##################### really the beginning of business
//
//#   here for the record are the notok codes
//#   since they will change when we make the login cgi C
//#   it's not worth doing any maintainable :)
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
//#
//# bail if not ssl
//notok('5') unless( $ENV{'HTTPS'} eq "on" );
//
//# check to see what cookies we have
//# if there is an error print the error page and bail out
//&cookie_test;
//
//# get the environment from the request
//my $q = new CGI;
//$q->import_names('Q');
//
//# use nice names
//if ( $Q::one ) {              # then it's a POST'ed submit of the login page
//    $args = $Q::eight;		
//    $uri = $Q::seven;
//    $host = $Q::six;
//    $method = $Q::five;
//    $version = $Q::four;
//    $creds = $Q::three;
//    $appid = $Q::two;
//    $appsrvid = $Q::one;
//    $fr = $Q::fr;
//    # the following will only be found in replys from the login page
//    $user = $Q::user;
//    $user =~ s/^\s*(\S+)\s*$/\1/;     # clean-up the username
//    # since people expect a uwnetid in the cookie not a krberos principal
//    $user = (split('@', $user))[0];
//    $pass = $Q::pass;
//    $pass2 = $Q::pass2;
//    # the following will only be found in POSTs or PUTs
//    $post_stuff = $Q::post_stuff;
//} 
//else {                         # then it's an original request to the login cgi
//    &decode_g_req_cookie;
//} 
//
//# check the user agent and maybe bail
//&check_user_agent;
//
//# allow for older versions that don't have froce_reauth
//if ( $fr eq "" ) {
//    $fr = "NFR";
//}
//
//# the main logic (see first comment block)
//if ( $Q::one ) {          # a reply from the login page
//    if ( ($res = &check_login) ne "success" ) {
//        log_message("Authentication failed: $user type: $creds $res");
//        my $message = $res;
//        if ( $res =~ /Authentication Failed/ ) {
//            $message = $pbc_em1_start . $auth_failed_message1 . $pbc_em1_end; 
//#            $message .= "<P>" . $pbc_em2_start . $auth_failed_message2 . $pbc_em2_end; 
//            $message .= "<P>" . $auth_failed_message2;
//        }
//        else {
//            log_error("Login problem: $res");
//        }
//        print_login_page("$message", "bad auth", $creds, 0);
//        exit;
//    }
//    log_message("Authentication success: $user type: $creds");
//}
//elsif ( $fr ne "NFR" ) {                           # force reauth
//    log_message ("user was forced to reauth by $host at $appid");
//    print_login_page("$print_login_please", "force reauth", $creds, 1);
//    exit;
//}
//elsif ( $ENV{'HTTP_COOKIE'} !~ /pubcookie_l=/ 
//     || $ENV{'HTTP_COOKIE'} =~ /pubcookie_l=;/ ) { # no l cookie 
//    print_login_page("$print_login_please", "no L cookie yet", $creds, 0);
//    exit;
//}
//elsif ( ($reason=&check_l_cookie) ne "success" ) { # problem with the l cookie
//    log_message("Login cookie bad: $reason");
//    print_login_page("$print_login_please", $reason, $creds, 1);
//    exit;
//}
//
//# the reward for a hard days work
//# user either authenticated correctly or had a valid l cookie
//log_message("Issuing cookies for $user at $ENV{REMOTE_ADDR} on $host at $appid");
//
//# setup to make the granting and login cookies
//my $serial = &get_next_serial;
//my $create_l_line =  url_encode($user) . " "
//                   . url_encode($appsrvid) . " " 
//                   . url_encode($appid) . " "     
//                   . "3 "     
//                   . url_encode($creds) . " "
//                   . $serial . " "
//                   . $crypt_key . " "
//                   . $cert_key_file;
//
//my $create_g_line =  url_encode($user) . " "
//                   . url_encode($appsrvid) . " " 
//                   . url_encode($appid) . " "     
//                   . "1 "     
//                   . url_encode($creds) . " "
//                   . $serial . " "
//                   . $crypt_key . " "
//                   . $cert_key_file;
//
//# mmmm, cook up them cookies
//my ($l_cookie, $g_cookie);
//if ( ($l_cookie = get_cookie_created($create_l_line)) eq "" ||
//     ($g_cookie = get_cookie_created($create_g_line)) eq "" ) {
//    my $message = $pbc_em1_start . $trouble_creating_cookie . $pbc_em1_end;
//    $message .= $pbc_em2_start . $problems_persist . $pbc_em2_end;
//    print_login_page($message, $reason, $creds, 0);
//    log_error("Not able to create cookie for user $user at $appsrvid-$appid");
//    exit;
//}
//
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
//if ( $post_stuff ) {
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
//    print_out("</TD></TR>\n");
//#    print_out("<NOSCRIPT>\n");
//    &print_uwnetid_logo;
//    print_out("<P>");
//    print_out("$pbc_post_no_js_text\n");
//#    print_out("</NOSCRIPT>\n");
//    print_out("</TD></TR></TABLE>\n");
//
//    # put submit at the bottom so it looks better and 
//    if ( $submit_value ) {
//        print "<INPUT TYPE=\"SUBMIT\" NAME=\"submit\" VALUE=\'$submit_value\'>\n";
//    }
//    else {
//        print "<INPUT TYPE=\"SUBMIT\" VALUE=\"$pbc_post_no_js_button\">\n";
//    }
//    print "</FORM>\n";
//#    print_out("<NOSCRIPT>\n");
//    &print_copyright;
//#    print_out("</NOSCRIPT>\n");
//    print "</CENTER>";
//    print "</BODY></HTML>\n";
//}
//else {
//# move refresh to body 
//#    print "Refresh: $refresh;URL=$redirect_dest\n";
//    print "Content-Type: text/html\n\n\n";
//    print "<HTML><HEAD>\n";
//    print "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"$refresh;URL=$redirect_dest\">\n";
//    print "<BODY BGCOLOR=\"white\">";
//    print "<!--redirecting to $redirect_dest-->";
//    print "</BODY></HTML>\n";
//}
//
//exit;
//
//
//######################### function land
//
//sub print_login_page {
//    my ($message, $reason, $creds, $need_clear_login) = @_;
//    my ($field_label, $word);
//
//    my $field_label2 = "";
//
//    if ( $creds eq "1" ) {
//        $field_label = $prompt_uwnetid;
//        $word = "password";
//    } 
//    elsif ( $creds eq "2" ) {
//        $field_label = "Invalid request\n";
//        $word = "INVALID REQUEST";
//    }
//    elsif ( $creds eq "3" ) {
//        $field_label2 = $prompt_securid;
//        $field_label = $prompt_uwnetid;
//        $word = "passwd and SecurID";
//    }
//    # this probably indicates a problem but ignore it for now
//    elsif ( $creds eq "0" ) {
//        $field_label = "<B>Password:</B><BR>\n";
//        $word = "password";
//    }
//
//    print "Content-Type: text/html\n";
//    if ( $need_clear_login ) {
//        print "Set-Cookie: " . &PBC_L_COOKIENAME . "=clear; domain=$hostname; path=$login_dir; expires=Fri, 11-Jan-1990 00:00:01 GMT; secure\n";
//    }
//    print "\n\n";
//
//    print_login_page_part1(1);
//
//    print "<P>$message</P>\n";
//    print "<!-- -- $reason -- -->\n";
//
//    # if everything is cool then give this nice text
//    if ( $message eq $print_login_please ) {
//        &print_login_page_part2a;
//    }
//    &print_login_page_part2b;
//
//    # seperate from above since this is where the form is
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
//}
//
//## if you need to splat on the login page
//#EOS
//#&splat;
//#print <<"EOS";
//
//sub splat {
//    print "<TABLE BORDER=\"3\">\n";
//        foreach my $k (sort keys %ENV ) {
//            my $bg;
//            if ( $k eq "HTTP_COOKIE" ) {
//               $bg = "yellow";
//            }
//            else {
//               $bg = "white";
//            }
//            print "<TR BGCOLOR=\"$bg\">\n";
//                print "<TD>\n";
//                    print "$k";
//                print "</TD>\n";
//                print "<TD>\n";
//                    print "$ENV{$k}";
//                print "</TD>\n";
//                print "\n";
//            print "</TR>\n";
//        }
//    print "</TABLE>\n";
//}
//
//sub splat_stderr {
//    print STDERR "<TABLE BORDER=\"3\">\n";
//        foreach my $k (sort keys %ENV ) {
//            my $bg;
//            if ( $k eq "HTTP_COOKIE" ) {
//               $bg = "yellow";
//            }
//            else {
//               $bg = "white";
//            }
//            print STDERR "<TR BGCOLOR=\"$bg\">\n";
//                print STDERR "<TD>\n";
//                    print STDERR "$k";
//                print STDERR "</TD>\n";
//                print STDERR "<TD>\n";
//                    print STDERR "$ENV{$k}";
//                print STDERR "</TD>\n";
//                print STDERR "\n";
//            print STDERR "</TR>\n";
//        }
//    print STDERR "</TABLE>\n";
//}
//
//# this is where we check the auth info
//# authsrv calls are meta-auth
//sub check_login {
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
//    return $ret;
//
//}
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
//sub cookie_test {
//
//    my $string_to_test_for = &PBC_FORM_MP_COOKIENAME;
//    if ( $ENV{'HTTP_COOKIE'} =~ /$string_to_test_for/ ) {
//        notok("formmultipart");
//        exit;
//    }
//
//    my $string_to_test_for = &PBC_G_REQ_COOKIENAME;
//    if ( $ENV{'HTTP_COOKIE'} !~ /$string_to_test_for/ ) {
//
//        my $string_to_test_for = &PBC_L_COOKIENAME;
//        if ( $ENV{'HTTP_COOKIE'} !~ /$string_to_test_for/ ) {
//            log_message("no granting req or login cookie from $ENV{'REMOTE_ADDR'}");
//            notok("no_g_or_l");
//        }
//        else {
//            log_message("no granting req, connection from $ENV{'REMOTE_ADDR'}");
//            notok("no_g");
//        }
//        exit;
//    }
//
//}
//
//sub check_l_cookie {
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
//    return "success";
//}
//
//sub get_cookie_created {
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
//    return $ret;
//}
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
//sub log_message {
//    my ($message) = @_;
//
//    print STDERR scalar localtime, " PUBCOOKIE_LOGINSRV_LOG ", $message, "\n";
//}
//
//sub log_error {
//    my ($message) = @_;
//
//    log_message("PUBCOOKIE SYSTEM ERROR: " . $message);
//    my $cmd = "$send_pilot_cmd pcookie_login:TRIG:1:pubcookie: $message: this trigger will have to manually cleared";
//    $cmd =~ s/(['"!])/\\$1/;
//    log_message("sending message to pilot $cmd");
//    `$cmd`;
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
//sub clean {
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
//    while ( ($i=index($c_string, $name, $i+1)) != -1 ) {
//        my $end = index($c_string, ";", $i);
//        $end = ( $end == -1 ) ? length($c_string) : $end;
//	my $len = $end - $i - length($name);
//        push( @cookies, substr($c_string, $i+length($name), $len) );
//    }
//
//    return @cookies;
//}
//
//sub check_user_agent {
// 
//  if ( ! open OK_AGENTS, $ok_browsers_file ) {
//      log_error("can't open ok browsers file: $ok_browsers_file, continuing w/o browser checking");
//      return(0);
//  }
//
//  my @ok_browsers = <OK_AGENTS>;
//  grep chomp($_), @ok_browsers;
//
//  if ( grep $ENV{'HTTP_USER_AGENT'} =~ /$_/, @ok_browsers ) {
//      return(0);
//  }
//  else {
//      log_message("bad agent: $ENV{'HTTP_USER_AGENT'} $host $uri");
//      notok("bad_agent"); 
//  }
//
//}
//
//
//################################### part 1
//sub print_login_page_part1 {
//    my ($focus) = @_;
//
//    print <<"EOS";
//<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
//<HTML>
//<HEAD>
//<TITLE>UW NetID Login</TITLE>
//</HEAD>
//
//EOS
//
//if ( $focus ) {
//    print "<BODY BGCOLOR=\"#FFFFFF\" onLoad=\"document.query.user.focus()\">\n";
//}
//else {
//    print "<BODY BGCOLOR=\"#FFFFFF\">\n";
//}
//
//    print <<"EOS";
//
//<CENTER>
//
//EOS
//
//    &print_table_start;
//    &print_uwnetid_logo;
//
//}
//
//################################### The beginning of the table
//sub print_table_start {
//
//    print "<TABLE CELLPADDING=0 CELLSPACING=0 BORDER=0 WIDTH=520>\n";
//
//}
//
//
//################################### UWNetID Logo
//sub print_uwnetid_logo {
//
//    print "<TR>\n<TD WIDTH=300 VALIGN=\"MIDDLE\">\n";
//    print "<IMG SRC=\"/images/login.gif\" ALT=\"UW NetID Login\" HEIGHT=\"64\" WIDTH=\"208\">\n";
//
//}
//
//################################### part 2a
//sub print_login_page_part2a {
//
//    print <<"EOS";
//<P>The resource you requested requires you to log in with your
//UW NetID and password.</P>
//
//EOS
//}
//
//################################### part 2b
//sub print_login_page_part2b {
//
//    print <<"EOS";
//<p>Need a UW NetID or forget your password? Go to the <a
//href="http://www.washington.edu/computing/uwnetid/">UW NetID Home
//Page</a> for help.</p>
//
//<p>Please send email to <a href="mailto:help\@cac.washington.edu">
//help\@cac.washington.edu</a> to report problems.</p>
//
//</TD>
//
//EOS
//}
//
//################################### part 3
//sub print_login_page_part3 {
//    my($word) = @_;
//
//    print <<"EOS";
//
//<TD WIDTH=9>&nbsp;</TD>
//
//<TD WIDTH=2 BGCOLOR="#000000"><IMG SRC="/images/1pixffcc33iystpiwfy.gif" WIDTH="1" HEIGHT="1" ALIGN="BOTTOM" ALT=""></TD>
//
//<TD WIDTH=9>&nbsp;</TD>
//
//<TD WIDTH=200 VALIGN="MIDDLE">
//<FORM METHOD="POST" ACTION="/" ENCTYPE="application/x-www-form-urlencoded" NAME="query">
//<p>Enter your UW NetID and $word below, then click the Login
//button.</p>
//<P>
//<B>UW NetID:</B><BR>
//<INPUT TYPE="TEXT" NAME="user" SIZE="20">
//<BR>
//<P>
//
//EOS
//
//# the bob@u text
//# <font size="-1">(If your UW email address is bob\@u.washington.edu,
//# then your UW NetID is bob.)</font>
//
//}
//
//
//################################### part 4
//sub print_login_page_part4 {
//
//    print <<"EOS";
//
//<P>
//<STRONG><INPUT TYPE="SUBMIT" NAME="submit" VALUE="Login"></STRONG>
//
//<INPUT TYPE="hidden" NAME="one" VALUE="$appsrvid">
//<INPUT TYPE="hidden" NAME="two" VALUE="$appid">
//<INPUT TYPE="hidden" NAME="three" VALUE="$creds">
//<INPUT TYPE="hidden" NAME="four" VALUE="$version">
//<INPUT TYPE="hidden" NAME="five" VALUE="$method">
//<INPUT TYPE="hidden" NAME="six" VALUE="$host">
//<INPUT TYPE="hidden" NAME="seven" VALUE="$uri">
//<INPUT TYPE="hidden" NAME="eight" VALUE="$args">
//<INPUT TYPE="hidden" NAME="fr" VALUE="$fr">
//<INPUT TYPE="hidden" NAME="post_stuff" VALUE="$post_stuff">
//
//</FORM>
//
//</TD>
//
//EOS
//}
//
//################################### part expire_info
//sub print_login_page_part_expire_info {
//
//    print <<"EOS";
//
//</TR>
//<TR>
//
//<TD COLSPAN=5 ALIGN=CENTER>
//
//<p><br>UW NetID login lasts 8 hours or until you exit your browser. To
//protect your privacy, <STRONG>exit your Web browser</STRONG> when you are
//done with this session.</p>
//
//</td>
//EOS
//}
//
//################################### part 5
//sub print_login_page_part5 {
//
//    print <<"EOS";
//
//</TR>
//<TR>
//
//<TD COLSPAN=5 ALIGN=CENTER>
//
//EOS
//    &print_copyright;
//    print <<"EOS";
//
//</td>
//</tr>
//
//</TABLE>
//
//</CENTER>
//</BODY></HTML>
//EOS
//}
//
//################################### print_problem 1
//sub print_problem1 {
//
//    print <<"EOS";
//
//<P><B><font size="+1" color="#FF0000">A problem has been detected!</font></B></P>
//
//<p><b><font size="+1">Either your browser is not configured to accept cookies, 
//or the URL address you opened contains a shortened domain name.</font></b></p>
//
//<p>Review <A HREF="http://www.washington.edu/computing/web/login-problems.html">Common
//Problems With the UW NetID Login Page</A> for further advice.</p>
//
//<p>&nbsp;</p>
//
//EOS
//}
//
//################################### print_problem 2 JS
//sub print_problem2_js {
//
//    print <<"EOS";
//
//    document.write("<P><B><font size=\\"+1\\" color=\\"#FF0000\\">A problem has been detected!</font></B></P>");
//    document.write("<p><b><font size=\\"+1\\">Either you tried to use the BACK button to return to pages you");
//    document.write(" visited before the UW NetID login page, or the URL address you opened contains a shortened");
//    document.write(" domain name. </font></b></p>");
//    document.write("<p>Review <A HREF=\\"http://www.washington.edu/computing/web/login-problems.html\\">Common");
//    document.write(" Problems With the UW NetID Login Page</A> for further advice.</p>");
//    document.write("<p>&nbsp;</p>");
//
//EOS
//}
//
//################################### print_problem 3 JS
//sub print_problem3_js {
//
//    print <<"EOS";
//
//    document.write("<P><B><font size=\\"+1\\" color=\\"#FF0000\\">This browser doesn't accept cookies!</font></B></P>");
//
//    document.write("<p><b><font size=\\"+1\\">Your browser must <a href=\\"http://www.washington.edu/computing/web/cookies.html\\">accept cookies</a> in");
//    document.write(" order to use the UW NetID login page.</font></b></p>");
//
//    document.write("<p>&nbsp;</p>");
//
//EOS
//}
//
//################################### print_problem 2
//sub print_problem2 {
//
//    print <<"EOS";
//
//<P><B><font size="+1" color="#FF0000">A problem has been detected!</font></B></P>
//
//<p><b><font size="+1">Either you tried to use the BACK button to return to pages you
//visited before the UW NetID login page, or the URL address you opened contains a shortened domain name. </font></b></p>
//
//<p>Review <A HREF="http://www.washington.edu/computing/web/login-problems.html">Common Problems With the UW NetID Login Page</A> for further advice.</p>
//
//<p>&nbsp;</p>
//
//EOS
//}
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
//################################### print_problem 4
//sub print_problem4 {
//
//    print <<"EOS";
//
//<P><B><font size="+1" color="#FF0000">A problem has been detected!</font></B></P>
//
//<p><b><font size="+1">The resource you requested requires "multipart/form-data"
//capabilities not supported by the UW NetID login page. Please email <a
//href="mailto:help\@cac.washington.edu">help\@cac.washington.edu</a> for further
//assistance.</font></b></p>
//
//<p>&nbsp;</p>
//
//EOS
//}
//
//################################### print_problem bad_agent
//sub print_problem_bad_agent {
//
//    print <<"EOS";
//
//<P><B><font size="+1" color="#FF0000">This browser is either incompatible or has serious security flaws.</font></B></P>
//
//<p><b><font size="+1">Please upgrade to the most recent version of either 
//<A HREF="http://home.netscape.com/computing/download/index.html">Netscape Navigator</A>,
//<A HREF="http://www.microsoft.com/windows/ie/default.htm">Internet Explorer</A>,
//or <A HREF="http://www.opera.com/">Opera</A>.  
//The browser you are using identifies itself as:<P><TT>$ENV{'HTTP_USER_AGENT'}</TT><P>  
//Please email <a href="mailto:help\@cac.washington.edu">help\@cac.washington.edu</a> for further assistance.</font></b></p> 
//
//<p>&nbsp;</p>
//
//EOS
//
//}
//
//################################### print copyright
//sub print_copyright {
//
//    print <<"EOS";
//<address>&#169; 1999 University of Washington</address>
//EOS
//
//}
//
//################################### print j_test
//sub print_j_test {
//
//    print <<"EOS";
//
//<SCRIPT LANGUAGE="JavaScript"><!--
//
//name = "cookie_test";
//s = (new Date().getSeconds());
//document.cookie = name + "=" + s;
//
//dc = document.cookie;
//prefix = name + "=";
//begin = dc.indexOf("; " + prefix);
//if (begin == -1) {
//    begin = dc.indexOf(prefix);
//    if (begin != 0) returned = "";
//} else
//    begin += 2;
//end = document.cookie.indexOf(";", begin);
//if (end == -1)
//    end = dc.length;
//returned = unescape(dc.substring(begin + prefix.length, end));
//
//if ( returned == s ) {
//EOS
//#------end
//
//    &print_problem2_js;
//
//    #----------start
//    print <<"EOS";
//    document.cookie = name + "=; expires=Thu, 01-Jan-70 00:00:01 GMT";
//}
//else {
//EOS
//#------end
//
//    &print_problem3_js;
//
//    #----------start
//    print <<"EOS";
//}
//
//// -->
//</SCRIPT>
//
//EOS
//
//
//}
//
//################################### print print_big_scary_err_page
//sub print_big_scary_err_page {
//
//    &print_j_test;
//
//    print_out("<NOSCRIPT>\n");
//
//    &print_problem1;
//
//    print_out("</NOSCRIPT>\n");
//
//}
//
//
//sub notok {
//    my ($notok_code) = @_;
//
//#   here for the record are the notok codes
//#   since they will change when we make the login cgi C
//#   it's not worth doing any maintainable :)
//# 1 - no cookies or non-fqdn 
//#     (http://staff.washington.edu/dors/projects/login/problem1.html)
//# no_g - 2 - backing in or non-fqd
//#     (http://staff.washington.edu/dors/projects/login/problem2.html)
//# 3 - no cookies!
//#     (http://staff.washington.edu/dors/projects/login/problem3.html)
//# formmultipart - 4 - multipart/form-data
//#     (http://staff.washington.edu/dors/projects/login/problem4.html)
//# 5 - not ssl, impossible but we still look for it.
//# bad_agent - reject this browser agent
//#
//
//    print_out("Content-Type: text/html\n");
//
//    my $string_to_test_for = &PBC_FORM_MP_COOKIENAME;
//    if ( $ENV{'HTTP_COOKIE'} =~ /$string_to_test_for/ ) {
//        print_out ("Set-Cookie: " . &PBC_FORM_MP_COOKIENAME . "=done; domain=.washington.edu; path=/; expires=Fri, 11-Jan-1990 00:00:01 GMT");
//    }
//
//    print_out("\n\n");
//
//    print_login_page_part1(0);
//
//    if ( $notok_code eq "no_g_or_l" ) {
//        &print_big_scary_err_page;
//    }
//    elsif( $notok_code eq "no_g" ) {
//        &print_problem2;
//    }
//    elsif( $notok_code eq "formmultipart" ) {
//        &print_problem4;
//    }
//    elsif( $notok_code eq '5' ) {
//        &print_problem5;
//    }
//    elsif( $notok_code eq "bad_agent" ) {
//        &print_problem_bad_agent;
//    }
//
//    &print_login_page_part5;
//
//    exit;
//}
//

  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*	general utility thingies                                            */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

void print_out(cahr *out) {
    printf ("%s\n", out);
}

char *get_my_hostname() {
    struct utsname	myname;

    if ( uname(&myname) < 0 )
        log_error("problem doing uname lookup");

}




//
//my $hostname = $ENV{'HTTP_HOST'};
//# if this is a test server use the test name
//if ( $hostname =~ /^pcookiel3/ ||
//     $hostname =~ /^weblogintest/ ) {
//    $hostname = "weblogintest.cac.washington.edu";
//}
//else {
//    $hostname = "weblogin.washington.edu";
//}
