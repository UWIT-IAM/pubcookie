#!/usr/local/bin/perl5

#
# $Id: index.cgi,v 1.1 1998-07-29 09:06:58 willey Exp $
#

use CGI;
use IPC::Open2;
use lib '/www/lib/auth', '/www/lib', '/usr/local/stronghold/pubcookie/';
require 'authsrv.pl';
require "pbc_config.ph";
require "pbc_version.ph";
require "pubcookie.ph";
$ENV{'PATH'} = '/bin:/usr/bin';

#
# four things are handled here
#   - first time: 
#         in: no L cookie, bunch of GET data
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
#  TODO:
#   pretty-ify login page
#   pretty-ify notok page
#

$hostname = "pcookiel1.cac.washington.edu";
$login_dir = "/login/get_pubcookie";
$refresh = "5";
$expire_login = 60 * 60 * 8;
$notok_needssl = "I'm sorry this page is only accessible via a SSL protected connection. <BR>\n";
$notok_nouser = "No login name\n";
$print_login_please = "Please Authenticate";
$create_pgm = "/usr/local/stronghold/pubcookie/pbc_create";
$verify_pgm = "/usr/local/stronghold/pubcookie/pbc_verify";
$user;

# bail if not ssl
notok($notok_needssl) unless( $ENV{'HTTPS'} eq "on" );

my $q = new CGI;
$q->import_names('Q');

print STDERR "hello\n";
if ( $ENV{'REQUEST_METHOD'} eq "POST" ) { # a reply from the login page
print STDERR "is a post\n";
    if ( ($res = &check_login) ne "success" ) {
        print_login("$print_login_please: login failed try again: $res");
        exit;
    }
}
elsif ( $ENV{'HTTP_COOKIE'} !~ /pubcookie_l=/ || $ENV{'HTTP_COOKIE'} =~ /pubcookie_l=;/ ) {  # no l cookie
    print STDERR "no l cookie\n";
    print_login("no L cookie yet: $print_login_please");
    exit;
}
elsif ( &check_l_cookie == 0 ) {
    print_login("L cookie not valid: $print_login_please");
    exit;
}

#my $uri = $query->param('uri');
#my $method = $query->param('method');
#my $port = $query->param('port');
#my $host = $query->param('host');
#my $args = $query->param('args');
#my $appid = $query->param('appid');
#my $appsrvid = $q->param('appsrvid');
#my $creds = $query->param('creds');
#my $version = $query->param('version');

# the reward for a hard days work

my $create_l_cmd =  "$create_pgm $user "
                   . $Q::appsrvid . " " 
                   . $Q::appid . " "     
                   . "3 "     
                   . $Q::creds;
my $create_g_cmd =  "$create_pgm $user "
                   . $Q::appsrvid . " " 
                   . $Q::appid . " "     
                   . "1 "     
                   . $Q::creds;

my $l_cookie = `$create_l_cmd`;
my $g_cookie = `$create_g_cmd`;

$redirect_dest = "https://". $Q::host . $Q::uri . $Q::url_args;

print <<"EOS";
Set-Cookie: pubcookie_g=$g_cookie; domain=.washington.edu path=/; secure
Set-Cookie: pubcookie_l=$l_cookie; domain=$hostname path=$login_dir; secure
Refresh: $refresh;URL=$redirect_dest
Content-Type: text/html

granting<BR>
$create_g_cmd
<P>
$g_cookie

login<BR>
$create_l_cmd
<P>
$l_cookie

<P>
igonna redirect to $redirect_dest
<BR>

EOS
&splat;
    print <<"EOS";

<HTML>
<HEAD>
</HEAD>
<BODY BGCOLOR="#FFFFFF">
</BODY>
</HTML>
EOS

# end of the show

exit;

sub notok {
    my ($reason) = @_;
    print <<"EOS";
Content-Type: text/html

<HTML>
<HEAD>
<TITLE>PubCookie Login</TITLE>
</HEAD>

<BODY>
	<H1>PubCookie Login</H1>

	$reason

	<P>
	You'll want: <A HREF="https://pcookiel1.cac.washington.edu/login/get_pubcookie/">https://pcookiel1.cac.washington.
	edu/login/get_pubcookie/</A>.  <BR>

	<P>
EOS

&splat;

print <<"EOS";
	Questions can be sent to:
	<A HREF="mailto:www-mgmt\@cac.washington.edu">www-mgmt\@cac.washington.edu</A>.
</BODY>
</HTML>
EOS

	exit 1;
}

sub print_login {
    my ($message, $creds) = @_;

print <<"EOS";
Content-Type: text/html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
<HTML>

<HEAD>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html;CHARSET=iso-8859-1">
	<META NAME="GENERATOR" Content="Visual Page 1.1 for Windows">
	<TITLE>Bench to Bedside and Beyond</TITLE>
</HEAD>

<BODY BGCOLOR="#FFFFFF" onLoad="document.query.user.focus()">

<H1>$message</H1>

<P ALIGN="CENTER"><IMG SRC="som.gif" WIDTH="454" HEIGHT="130" ALIGN="BOTTOM" BORDER="0" ALT="Bench to Bedside and Beyond Logo"></P>

<P>If you are not currently participating in the Bench to Bedside and Beyond remote access pilot follow these
<A HREF="deinstall.html">instructions</A> to disable this login and access the University of Washington directly. Otherwise, enter your login ID and password.</P>

<FORM ACTION="index.cgi" METHOD="POST" ENCTYPE="application/x-www-form-urlencoded" NAME="query">

<P>
<TABLE BORDER="1" CELLPADDING="5" WIDTH="100%">
	<TR>
		<TD WIDTH="50%">
			<TABLE BORDER="0" WIDTH="100%">
				<TR>
					<TD COLSPAN="2">
						<P ALIGN="CENTER"><FONT SIZE="4"><B>User Validation</B></FONT>
					</TD>
				</TR>
				<TR>
					<TD WIDTH="47%">
						<P ALIGN="RIGHT"><FONT SIZE="2"><B>Login ID:</B> <BR>
						(homer, dante, aagaard)</FONT>
					</TD>
					<TD WIDTH="53%"><INPUT TYPE="TEXT" NAME="user" SIZE="15"></TD>
				</TR>
				<TR>
					<TD WIDTH="47%">
						<P ALIGN="RIGHT"><FONT SIZE="2"><B>Password:</B></FONT>
					</TD>
					<TD WIDTH="53%"><INPUT TYPE="PASSWORD" NAME="pass" SIZE="15"></TD>
				</TR>
				<TR>
					<TD WIDTH="47%">
					</TD>
					<TD WIDTH="53%"><INPUT TYPE="SUBMIT" VALUE="Submit" </TD>
				</TR>
			</TABLE>
		</TD>
		<TD WIDTH="50%">
			<P><FONT COLOR="#CC0000"><B>Please Note:</B></FONT>


			<BLOCKQUOTE>
			<P><FONT SIZE="2">Logins must be revalidated after 30<BR>
			minutes of inactivity or 8 hours of <BR>
			continuous use.</FONT>
			</BLOCKQUOTE>
		</TD>
	</TR>
</TABLE>

<INPUT TYPE="hidden" NAME="uri" VALUE="$Q::uri">
<INPUT TYPE="hidden" NAME="url_args" VALUE="$Q::url_args">
<INPUT TYPE="hidden" NAME="method" VALUE="$Q::method">
<INPUT TYPE="hidden" NAME="port" VALUE="$Q::port">
<INPUT TYPE="hidden" NAME="host" VALUE="$Q::host">
<INPUT TYPE="hidden" NAME="args" VALUE="$Q::args">
<INPUT TYPE="hidden" NAME="appid" VALUE="$Q::appid">
<INPUT TYPE="hidden" NAME="appsrvid" VALUE="$Q::appsrvid">
<INPUT TYPE="hidden" NAME="creds" VALUE="$Q::creds">
<INPUT TYPE="hidden" NAME="version" VALUE="$Q::version">

<BR>
The contents of this form will be encrypted to protect your privacy.
Your browser should signify this by having a lock <IMG SRC="netlock.gif">or an unbroken key <IMG SRC="netkey.gif">in the lower left of your Netscape browser
or a lock <IMG SRC="netlock.gif">on the lower right of your Internet Explorer browser. If one of these symbols does not appear in your
browser or you have questions about the B3 remote services send us <A HREF="mailto:extaccess-help\@u.washington.edu">email</A>.

<HR ALIGN="CENTER" WIDTH="75%">

<CENTER>
<FONT SIZE="2">Find out </FONT><A HREF="proxy.html"><FONT SIZE="2">more about how this access control works</FONT></A><FONT SIZE="2">.</FONT></CENTER>

</FORM>
<ADDRESS>
  <CENTER>
    &#169; 1998 University of Washington
  </CENTER>
</ADDRESS>

EOS
&splat;
    print <<"EOS";

</BODY>

</HTML>

EOS

}

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

sub check_login {

    if ( authsrv::authenticate(\$result, 10, $$, 'auth-only', 0, 0,
                                        [ 'uapasswd' ],
                                        {
                                            'username' => $Q::user,
                                            'uapasswd' => $Q::pass
                                        }) ) {
        $main::user = $Q::user;
        return "success";
    }
    else {
        return $result;    
    }

}

sub check_l_cookie {
    my ($user, $version, $type, $creds, $appsrv_id, $app_id, $create_ts, $last_ts);

    $ENV{'HTTP_COOKIE'} =~ m/pubcookie_l=(\S+==)/;
    my $login_cookie = $1;

print STDERR "\nlogin cookie is: $login_cookie\n";
print STDERR "\nall cookies are$ENV{'HTTP_COOKIE'}\n";

    my $cmd = "$verify_pgm 3";

print STDERR "\nverify command is $cmd";

    if( ! open2(RDR, WTR, $cmd) ) {
        print STDERR "check_l_cookie: open2 of cmd $cmd failed $!\n";
        return 0;
    }
    print WTR $login_cookie;
    close WTR;
    while(<RDR>) {
print STDERR "\nverify command $_";
        $user = $1 if ( /user: (.*)(\s|$)/ );
        $version = $1 if ( /version: (.*)(\s|$)/ );
        $type = $1 if ( /type: (.)/ );
        $creds = $1 if ( /creds: (.)/ );
        $appsrv_id = $1 if ( /appsrv_id: (.*)(\s|$)/ );
        $app_id = $1 if ( /app_id: (.*)(\s|$)/ );
        $create_ts = $1 if ( /create_ts: (\d+)(\s|$)/ );
        $last_ts = $1 if ( /last_ts: (\d+)(\s|$)/ );
    }
    if ( ! $user ) {
        return 0;
    }
    if ( ($create_ts + $expire_login) < ($t=time) ) {
print STDERR "expired login cookie: created: $create_ts timeout: $expire_login now: $t\n";
        return 0;
    }
    if ( $creds ne $Q::creds ) {
print STDERR "wrong creds: from login cookie $creds from granting request $Q::creds\n";
        return 0;
    }
    if ( $version ne $Q::version ) {
print STDERR "wrong version: from login cookie $version from granting request $Q::version\n";
        return 0;
    }
    if ( $type ne '3' ) {
        return 0;
    }
    $main::user = $user;
    return 1;
}

