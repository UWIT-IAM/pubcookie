#!/usr/local/bin/perl5

use CGI;
use IPC::Open2;
use IPC::Open3;
use MIME::Base64;
# meta-auth stuff comes from /www/lib/auth
# some pubcookie defines fomr from /usr/local/pubcookie/
use lib '/www/lib/auth', '/usr/local/pubcookie/';
require 'authsrv.pl';
require "pbc_config.ph";
require "pbc_version.ph";
require "pubcookie.ph";
$ENV{'PATH'} = '/bin:/usr/bin';

#
# four cases for the main thingie
#   - first time or force_reauth: 
#         in: no L cookie, bunch of GET data
#               OR force_reauth info in GET
#         out: the login page (includes data from get)
#
#   - not first time (have L cookie) but L cookie expired or invalid
#         in: expired or invalid L cookie, bunch of GET data
#         out: the login page (includes data from get)
#
#   - not first time (have L cookie) L cookie not expired and valid
#         in: valid L cookie, bunch of GET data
#         out: L & G cookies redirect (username comes from cookie)
#
#   - POST from login page
#         in: POST data that include creds
#         process: validate creds
#         out: if successful L & G cookies redirect else login page
#
#

$host = `hostname`;
chomp($host);
#$hostname = "$host.cac.washington.edu";
$hostname = $ENV{'HTTP_HOST'};

$login_dir = "/";
$refresh = "0";
$expire_login = 60 * 60 * 8;

# messages that get sent to the user
$notok_needssl = "I'm sorry this page is only accessible via a SSL protected connection. <BR>\n";
$notok_nouser = "No login name\n";
$notok_backedin = "Hello, you used that BACK button to get here didn't you.  Sorry it doesn't work.\n";

$print_login_please = "Please log in.";
$auth_failed_message = "Login failed. Please re-enter.";
$cookie_test_fail_message = "This browser doesn't accept cookies! <BR><A HREF=\"http://www.washington.edu/computing/web/cookies.html\">Learn how to turn them on.</A>";
$no_g_req_fail_message = "Where did you come from? <BR><A HREF=\"http://www.washington.edu/computing/web/cookies.html\">Learn more.</A>";

$prompt_uwnetid = "<B>Password:</B><BR>\n";
$prompt_securid = "<B>SecurID:</B><BR>\n";

# how we accentuate WARNING messages
$pbc_em_start = "<B><font color=\"#FF0000\" size=\"+1\">"; 
$pbc_em_end = "</font></B><BR>";

# some misc settings
$serial_file = "/tmp/s";
$first_serial = 23;
$accept_cookies = 1;
$granting_request = 1;


# bail if not ssl
notok($notok_needssl) unless( $ENV{'HTTPS'} eq "on" );

# check to see what cookies we have
&check_cookie_test;

# these two will print an 'error' page and exit
&notok_no_cookies unless ( $accept_cookies );
&notok_no_g_req unless ( $granting_request );

# get the environment from the request
my $q = new CGI;
$q->import_names('Q');

# use nice names
if ( $Q::one ) {
    $args = $Q::eight;		
    $uri = $Q::seven;
    $host = $Q::six;
    $method = $Q::five;
    $version = $Q::four;
    $creds = $Q::three;
    $appid = $Q::two;
    $appsrvid = $Q::one;
    $fr = $Q::fr;
    # the following will only be found in posts
    $user = $Q::user;
    $pass = $Q::pass;
    $pass2 = $Q::pass2;
} 
else {
    &decode_g_req_cookie;
} 

# allow for older versions that don't have froce_reauth
if ( $fr eq "" ) {
    $fr = "NFR";
}

# first do some things to conpensate for old versions
if ( $version eq "a1" ) {
    warn_old_module_version($host, $version, "old create");
    $create_pgm = "/usr/local/pubcookie/pbc_create.a1";
    $verify_pgm = "/usr/local/pubcookie/pbc_verify.a1";
} 
else {
    $create_pgm = "/usr/local/pubcookie/pbc_create";
    $verify_pgm = "/usr/local/pubcookie/pbc_verify";
}

if ( $ENV{'REQUEST_METHOD'} eq "POST" ) { # a reply from the login page
    if ( ($res = &check_login) ne "success" ) {
        log_message("Authentication failed: $user: $res");
        my $message = $res;
        if ( $res =~ /Authentication Failed/ ) {
            $message = $pbc_em_start . $auth_failed_message . $pbc_em_end; 
        }
        print_login_page("$message", "bad auth", $creds, 0);
        exit;
    }
    log_message("Authentication success: $user");
}
elsif ( $fr ne "NFR" ) {                           # force reauth
    log_message ("user was forced to reauth by $host at $uri");
    print_login_page("$print_login_please", "force reauth", $creds, 1);
    exit;
}
elsif ( $ENV{'HTTP_COOKIE'} !~ /pubcookie_l=/ 
     || $ENV{'HTTP_COOKIE'} =~ /pubcookie_l=;/ ) { # no l cookie 
    print_login_page("$print_login_please", "no L cookie yet", $creds, 0);
    exit;
}
elsif ( ($reason=&check_l_cookie) ne "success" ) { # problem with the l cookie
    log_message("Login cookie bad: $reason");
    print_login_page("$print_login_please", $reason, $creds, 1);
    exit;
}

# the reward for a hard days work
# user either authenticated correctly or had a valid l cookie
log_message("Issuing cookies for $user on $host at $appid");

# make the granting and login cookies
my $serial = &get_next_serial;
my $create_l_cmd =  $create_pgm . " "
                   . url_encode($user) . " "
                   . url_encode($appsrvid) . " " 
                   . url_encode($appid) . " "     
                   . "3 "     
                   . url_encode($creds) . " "
                   . $serial;

my $create_g_cmd =  $create_pgm . " ". url_encode($user) . " "
                   . url_encode($appsrvid) . " " 
                   . url_encode($appid) . " "     
                   . "1 "     
                   . url_encode($creds) . " "
                   . $serial;

my $l_cookie = get_cookie_created($create_l_cmd);
my $g_cookie = get_cookie_created($create_g_cmd);

my $g_set_cookie = "Set-Cookie: pubcookie_g=$g_cookie; domain=.washington.edu; path=/; secure";
my $s_set_cookie = "Set-Cookie: pubcookie_l=$l_cookie; domain=$hostname; path=$login_dir; secure";
my $clear_g_req_cookie = "Set-Cookie: " . &PBC_G_REQ_COOKIENAME . "=done; domain=.washington.edu; path=/; expires=Fri, 11-Jan-1990 00:00:01 GMT";


# cook up the url to send the browser back to
if ( $fr eq "NFR" || $fr eq "" ) {
    $redirect_uri = $uri;
}
else {
    if ( $fr =~ /^\// ) {
        $redirect_uri = $fr;
    } 
    else {
        $redirect_uri = "/" . $fr;
    } 
}

$redirect_dest = "https://". $host . $redirect_uri;
if ( $args ) {
    $redirect_dest .= "?" . decode_base64($args);
}


# now blat out the redirect page
print <<"EOS";
$g_set_cookie
$s_set_cookie
$clear_g_req_cookie
Refresh: $refresh;URL=$redirect_dest
Content-Type: text/html


<HTML><BODY BGCOLOR="#FFFFFF"></BODY></HTML>
EOS

exit;



sub notok {
    my ($reason) = @_;
    print <<"EOS";
Content-Type: text/html

<HTML>
<HEAD> 
<TITLE>UW NetID Login</TITLE> 
</HEAD>

<BODY>
<P>$reason</P>


<P>
You'll want: <A HREF="https://$hostname/">https://$hostname/</A>.  <BR>

<P>
EOS

&splat;

print <<"EOS";
Questions can be sent to:
<A HREF="mailto:pubcookie\@cac.washington.edu">pubcookie\@cac.washington.edu</A>.
</BODY>
</HTML>
EOS

exit 1;
}

sub print_login_page {
    my ($message, $reason, $creds, $need_clear_login) = @_;

    my $field_label2 = "";

    if ( $creds eq "1" ) {
        $field_label = $prompt_uwnetid;
        $word = "password";
    } 
    elsif ( $creds eq "2" ) {
        $field_label = "Invalid request\n";
        $word = "INVALID REQUEST";
    }
    elsif ( $creds eq "3" ) {
        $field_label = $prompt_securid;
        $field_label2 = $prompt_uwnetid;
        $word = "passwd and SecurID";
    }
    # this probably indicates a problem but ignore it for now
    elsif ( $creds eq "0" ) {
        $field_label = "<B>Password:</B><BR>\n";
        $word = "password";
    }

    print "Content-Type: text/html\n";
    if ( $need_clear_login ) {
        print "Set-Cookie: " . &PBC_L_COOKIENAME . "=clear; domain=$hostname; path=$login_dir; expires=Fri, 11-Jan-1990 00:00:01 GMT; secure\n";
    }
    print "\n\n";

    &print_login_page_part1;

    print "<P>$message</P>\n";
    print "<!-- -- $reason -- -->\n";

    &check_user_agent;

    &print_login_page_part2;

    # seperate from above since this is where the form is
    &print_login_page_part3;

    print $field_label;
    print "<INPUT TYPE=\"";
    if ( $field_label eq $prompt_uwnetid ) {
        print "PASSWORD";
    }
    print "\" NAME=\"pass\" SIZE=\"20\">\n";
        
    if ( $field_label2 eq $prompt_uwnetid ) {
        print $field_label2;
        print "<INPUT TYPE=\"";
        print "PASSWORD\" NAME=\"pass2\" SIZE=\"20\">\n";
    }
    elsif ( $field_label2 eq $prompt_securid ) {
        print $field_label2;
        print "<INPUT TYPE=\"";
        print "TEXT\" NAME=\"pass2\" SIZE=\"20\">\n";
    }

    &print_login_page_part4;

    &print_login_page_part5;

}

## if you need to splat on the login page
#EOS
#&splat;
#print <<"EOS";

sub splat {
    print "<TABLE BORDER=\"3\">\n";
        foreach my $k (sort keys %ENV ) {
            my $bg;
            if ( $k eq "HTTP_COOKIE" ) {
               $bg = "yellow";
            }
            else {
               $bg = "white";
            }
            print "<TR BGCOLOR=\"$bg\">\n";
                print "<TD>\n";
                    print "$k";
                print "</TD>\n";
                print "<TD>\n";
                    print "$ENV{$k}";
                print "</TD>\n";
                print "\n";
            print "</TR>\n";
        }
    print "</TABLE>\n";
}

sub splat_stderr {
    print STDERR "<TABLE BORDER=\"3\">\n";
        foreach my $k (sort keys %ENV ) {
            my $bg;
            if ( $k eq "HTTP_COOKIE" ) {
               $bg = "yellow";
            }
            else {
               $bg = "white";
            }
            print STDERR "<TR BGCOLOR=\"$bg\">\n";
                print STDERR "<TD>\n";
                    print STDERR "$k";
                print STDERR "</TD>\n";
                print STDERR "<TD>\n";
                    print STDERR "$ENV{$k}";
                print STDERR "</TD>\n";
                print STDERR "\n";
            print STDERR "</TR>\n";
        }
    print STDERR "</TABLE>\n";
}

# this is where we check the auth info
# authsrv calls are meta-auth
sub check_login {
    my $ret = "invalid creds";

    if ( $creds eq "1" ) {
        $ret = check_login_uwnetid($user, $pass);
    }
    elsif ( $creds eq "3" ) {
        if ( ($ret = check_login_securid($user, $pass)) eq "success" ) {
            $ret = check_login_uwnetid($user, $pass2);
        }
        else {
            return $ret;
        }
    }

    return $ret;

}

sub check_login_uwnetid {
    my ($user, $pass) = @_;

    if ( authsrv::authenticate(\$result, 10, $$, 'auth-only', 0, 0,
                                        [ 'uapasswd' ],
                                        {
                                            'username' => $user,
                                            'uapasswd' => $pass
                                        }) ) {
        $main::user = $user;
        return "success";
    }
    else {
        return $result . " uwnetid";    
    }

}

sub check_login_securid {
    my ($user, $pass) = @_;
    my $result;

print STDERR "about to check $result, $user $pass\n";
    if ( authsrv::authenticate(\$result, 10, $$, 'auth-only', 0, 0,
                                        [ 'securid' ],
                                        {
                                            'username' => $user,
                                            'sid' => $pass
                                        }) ) {
        $main::user = $user;
        return "success";
    }
    else {
print STDERR "crap $result, $user $pass\n";
        return $result . " securid";    
    }

}

sub check_cookie_test {

    if ( $version eq "a2" || $version eq "a3" || $version eq "a1" ) {
        # these old versions used a different cookie 
        # to test for in the cookie test
        return;
    }
    else {
        my $string_to_test_for = &PBC_G_REQ_COOKIENAME;
        if ( $ENV{'HTTP_COOKIE'} !~ /$string_to_test_for/ ) {
            log_message("client came in w/o granting req for $ENV{'REQUEST_URI'}");
            $main::granting_request = 0;

            my $string_to_test_for = &PBC_L_COOKIENAME;
            if ( $ENV{'HTTP_COOKIE'} !~ /$string_to_test_for/ ) {
                log_message("client came in w/o granting req or login cookie $ENV{'REQUEST_URI'}");
                $main::accept_cookies = 0;
            }
        }
    }

}

sub check_l_cookie {
    my ($c_user, $c_version, $c_type, $c_creds, $c_appsrv_id, $c_app_id, $c_create_ts, $c_last_ts);

    # get the login request cookie(s)
    my @cookies = get_cookie_fromenv(&PBC_L_COOKIENAME);

    # maybe deny them if they have muliple login request cookies
    # for now just log it.
    if ( scalar @cookies > 1 ) {
        log_message("MULTIPLE login request cookies? for $ENV{'REQUEST_URI'}");
    }
    elsif ( scalar @cookies == 0 ) {
        log_message("FAIL zero login cookies? for $ENV{'REQUEST_URI'}");
        return 0;
    }

    my $login_cookie = $cookies[-1];

    my $cmd = "$verify_pgm 3";
    if( ! open3(WTR, RDR, ERR, $cmd) ) {
        log_message ("check_l_cookie: open2 of cmd $cmd failed $!");
        return "system_problem";
    }
    print WTR $login_cookie;
    close WTR;
    while(<ERR>) {
    }
    while(<RDR>) {
        chomp;
        $c_user = $1 if ( /user: (.*)(\s|$)/ );
        $c_version = $1 if ( /version: (.*)(\s|$)/ );
        $c_type = $1 if ( /type: (.)/ );
        $c_creds = $1 if ( /creds: (.)/ );
        $c_appsrv_id = $1 if ( /appsrv_id: (.*)(\s|$)/ );
        $c_app_id = $1 if ( /app_id: (.*)(\s|$)/ );
        $c_create_ts = $1 if ( /create_ts: (\d+)(\s|$)/ );
        $c_last_ts = $1 if ( /last_ts: (\d+)(\s|$)/ );
    }
    if ( ! $c_user ) {
        log_message("no user from login cookie?: $user");
        return "malformed";
    }
    if ( ($c_create_ts + $expire_login) < ($t=time) ) {
        log_message("expired login cookie: created: $c_create_ts timeout: $expire_login seconds now: $t");
        return "expired";
    }

    if ( $c_creds ne $creds ) {
        if ( $creds eq "1" ) {
            if ( $c_creds ne "3" ) {
                return "wrong_creds: from login cookie: $c_creds from request: $creds";
            }
        }
        else {
            return "wrong_creds: from login cookie: $c_creds from request: $creds";
        }
    }

    # check version
    if ( substr($c_version, 0, 1) ne substr($version, 0, 1) ) {
        log_message ("wrong major version: from login cookie $c_version, from granting request $version");
        return "wrong_version";
    }
    if ( substr($c_version, 1, 1) ne substr($version, 1, 1) ) {
        log_message("WARNING: wrong minor version: from login cookie $c_version, from granting request $version, for host $host, it's ok for now");
    }

    # make sure it's a login cookie
    if ( $c_type ne '3' ) {
        return "malformed";
    }

    $user = $c_user;
    return "success";
}

sub get_cookie_created {
    my($line) = @_;
    my $ret;

    if( ! open2(RDR, WTR, $line) ) {
        log_message("get_cookie_created: open2 of cmd $create_pgm failed $!");
        return 0;
    }
    print WTR $line;
    close WTR;
    $ret = <RDR>;
    return $ret;
}

sub url_encode {
    my ($in) = @_;
    my $out = $in;
    $out =~ s/%/%25/g;
    $out =~ s/&/%26/g;
    $out =~ s/\+/%2B/g;
    $out =~ s/:/%3A/g;
    $out =~ s/;/%3B/g;
    $out =~ s/=/%3D/g;
    $out =~ s/\?/%3F/g;
    $out =~ s/ /+/g;
    return $out;
}

sub warn_old_module_version {
    my ($host, $version, $notes) = @_;

    log_message ("WARNING old module version running on $host: version: $version why i know: $notes");
}

sub log_message {
    my ($message) = @_;

    print STDERR scalar localtime, " PUBCOOKIE_LOGINSRV_LOG ", $message, "\n";
}

sub get_next_serial {
    return 1;
}

sub decode_g_req_cookie {
    
    # get the granting request cookie(s)
    my @g_req_cookie = get_cookie_fromenv(&PBC_G_REQ_COOKIENAME);

    # maybe deny them if they have muliple granting request cookies
    # for now just log it.
    if ( scalar @g_req_cookie > 1 ) {
        log_message("MULTIPLE granting request cookies? for $ENV{'REQUEST_URI'}");
    }
    elsif ( scalar @g_req_cookie == 0 ) {
        return 0;
    }

    # if there are multiple use the last one
    my $arg_line = decode_base64($g_req_cookie[-1]);

    my $g_req_args = new CGI($arg_line);
    $g_req_args->import_names('QS');

    $args = $QS::eight;		
    $uri = $QS::seven;
    $host = $QS::six;
    $method = $QS::five;
    $version = $QS::four;
    $creds = $QS::three;
    $appid = $QS::two;
    $appsrvid = $QS::one;
    $fr = $QS::fr;

}

# this allows for multiple cookies of the same name
# is that a good thing?
sub get_cookie_fromenv {
    my ($name) = @_;
    my $i = -1;
    my @cookies;

    $name .= "=";
    $c_string = $ENV{'HTTP_COOKIE'};

    while ( ($i=index($c_string, $name, $i+1)) != -1 ) {
        my $end = index($c_string, ";", $i);
        $end = ( $end == -1 ) ? length($c_string) : $end;
	my $len = $end - $i - length($name);
        push( @cookies, substr($c_string, $i+length($name), $len) );
    }

    return @cookies;
}

sub check_user_agent {
 
#$ENV{'HTTP_USER_AGENT'};

}


################################### part 1
sub print_login_page_part1 {

    print <<"EOS";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
<HTML>
<HEAD>
<TITLE>UW NetID Login</TITLE>
</HEAD>

<BODY BGCOLOR="#FFFFFF" onLoad="document.query.user.focus()">

<CENTER>

<TABLE CELLPADDING=0 CELLSPACING=0 BORDER=0 WIDTH=520>
<TR>
<TD WIDTH=300 VALIGN="MIDDLE">
<IMG SRC="/images/login.gif" ALT="UW NetID Login" HEIGHT="64" WIDTH="208">

EOS
}

################################### part 2
sub print_login_page_part2 {

    print <<"EOS";
<P>The resource you requested requires you to log in with your
UW NetID and password.</P>

<p>Please contact <A href="mailto:help\@cac.washington.edu">help\@cac</A> if the address of this page <strong>is not</strong>
<b>https://$hostname$login_dir</b>.</p>

<p>Need a UW NetID or forget your password? Go to the <a
href="http://www.washington.edu/computing/uwnetid/">UW NetID Home
Page</a> for help.</p>

</TD>

EOS
}

################################### part 3
sub print_login_page_part3 {

    print <<"EOS";

<TD WIDTH=9>&nbsp;</TD>

<TD WIDTH=2 BGCOLOR="#000000"><IMG SRC="/images/1pixffcc33iystpiwfy.gif" WIDTH="1" HEIGHT="1" ALIGN="BOTTOM" ALT=""></TD>

<TD WIDTH=9>&nbsp;</TD>

<TD WIDTH=200 VALIGN="MIDDLE">
<FORM METHOD="POST" ACTION="index.cgi" ENCTYPE="application/x-www-form-urlencoded" NAME="query">
<p>Enter your UW NetID and $word below, then click the Login
button.</p>
<P>
<B>UW NetID:</B><br>
<INPUT TYPE="TEXT" NAME="user" SIZE="20">
<P>

EOS
}


################################### part 4
sub print_login_page_part4 {

    print <<"EOS";

<P>
<STRONG><INPUT TYPE="SUBMIT" NAME="submit" VALUE="Login"></STRONG>

<INPUT TYPE="hidden" NAME="one" VALUE="$appsrvid">
<INPUT TYPE="hidden" NAME="two" VALUE="$appid">
<INPUT TYPE="hidden" NAME="three" VALUE="$creds">
<INPUT TYPE="hidden" NAME="four" VALUE="$version">
<INPUT TYPE="hidden" NAME="five" VALUE="$method">
<INPUT TYPE="hidden" NAME="six" VALUE="$host">
<INPUT TYPE="hidden" NAME="seven" VALUE="$uri">
<INPUT TYPE="hidden" NAME="eight" VALUE="$args">
<INPUT TYPE="hidden" NAME="fr" VALUE="$fr">

</FORM>

</TD>

EOS
}

################################### part 5
sub print_login_page_part5 {

    print <<"EOS";

</TR>
<TR>

<TD COLSPAN=5 ALIGN=CENTER>

<p><br>UW NetID login lasts 8 hours or until you exit your browser. To
protect your privacy, <STRONG>exit your Web browser</STRONG> when you are
done with this session.</p>

<address>&#169; 1999 University of Washington</address>

</td>
</tr>

</TABLE>

</CENTER>
</BODY></HTML>
EOS
}

sub notok_no_cookies {

    print "Content-Type: text/html\n";
    print "\n\n";

    &print_login_page_part1;

    print("<P>\n" . $pbc_em_start . $cookie_test_fail_message . $pbc_em_end);

    &print_login_page_part2;

    &print_login_page_part5;

    exit;
}

sub notok_no_g_req {

    print "Content-Type: text/html\n";
    print "\n\n";

    &print_login_page_part1;

    print("<P>\n" . $pbc_em_start . $no_g_req_fail_message . $pbc_em_end);

    &print_login_page_part2;

    &print_login_page_part5;

    exit;
}
