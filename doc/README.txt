     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


Pubcookie / Weblogin Authentication Service documentation is available at:
http://www.washington.edu/computing/pubcookie/


*** Apache Module (mod_pubcookie) ***

Installation specific docs live at:
http://www.washington.edu/computing/pubcookie/apache/install.html

The Apache module (mod_pubcookie) distribution contains the following files: 
	README.txt - this file
       	CHANGES.mod_pubcookie.txt - version history
       	LICENSE.txt - you hav the right ...
       	Makefile.tmpl - makefile template for mod_pubcookie
       	Makefile.axps - makefile to make mod_pubcookie as a DSO object
       	base64.c
       	candv.c
       	dtest.c
       	libpubcookie.c
       	libpubcookie.h
       	mod_pubcookie.c
       	pbc_config.h
       	pbc_version.h
       	pubcookie.h


*** Login Server ***

Login server installation documentation, lives in INSTALL.login

The pubcookie login server distribution contains the following files:
        NEW_SITE.txt - overview for new site installations
	CHANGES.login.txt - version history
	INSTALL.login.txt - installation docs
	Makefile.index.cgi - Makefile for login cgi
	Makefile - Makefile for tools and junk
	README.txt - this file
       	LICENSE.txt - you hav the right ...
	base64.c
	index.cgi.c
	index.cgi.h
	index.cgi_krb.c
	index.cgi_securid.c
	libpubcookie.c
	libpubcookie.h
	securid.c
	securid.h
	pbc_key_generic.c
	pbc_key_local.c
	pbc_key_local.txt
	pbc_config.h
	pbc_version.h
	pubcookie.h
        dtest.c
        what_is_my_ip.c
        pbc_create.c
        pbc_verify.c
        candv.c
	make_crypted_bit.c
	check_crypted_bit.c
	Test_local_blob.bat - windows batchfile for testing crypto functions
	Test_login_blob.bat - windows batchfile for testing key from admin
	check_crypted_blob.exe - windows binary for genrating crypted blob
	make_crypted_blob.exe - windows binary for decrypting/checking blob
	ssleay.exe - windows OpenSSL binary for utility functions
	contrib/*   


$Id: README.txt,v 1.13 2002-01-11 23:44:10 willey Exp $

