
/* Copyright 1999, University of Washington.  All rights reserved. */

/*
    $Id: pbc_create.c,v 1.11 2001-08-29 18:18:59 willey Exp $
 */

/* this is not meant to be user friendly, no friendlyness for anyone          */
/*   but us and we have the src code                                          */
/*                                                                            */
/* the big news is that arguments come in on stdin not the command line!!!!   */
/*                                                                            */
/* args are: user appsrvid appid type creds serial crypt_file cert_key_file */
/*    (anything too big is just truncated)                                    */
/*      since i'm lazy the argments aren't at all parsed, if you              */
/*	want to specify a cert_file you must also specifiy a crypt key        */
/*                                                                            */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include <stdlib.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int main(int argc, char **argv) {
    md_context_plus 	*ctx_plus;
    crypt_stuff         *c_stuff;

    unsigned char 	user[PBC_USER_LEN];
    unsigned char 	appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char 	appid[PBC_APP_ID_LEN];
    unsigned char 	type;
    unsigned char 	creds;
    int 		serial;

    unsigned char	crypt_keyfile[PBC_1K];
    unsigned char	cert_keyfile[PBC_1K];

    unsigned char	user_buf[PBC_1K];
    unsigned char	appsrvid_buf[PBC_1K];
    unsigned char	appid_buf[PBC_1K];

    unsigned char 	*cookie;

    if( fscanf( stdin, "%1023s%1023s%1023s %c %c %d %1023s%1023s\n", 
                       user_buf,                 
		       appsrvid_buf, 
		       appid_buf,
		       &type,
		       &creds,
		       &serial,
		       crypt_keyfile,
		       cert_keyfile) != 8 ) {
	exit(1);
    }

    /* move the arguments out of buffers and right size them */
    strncpy(user, user_buf, sizeof(user));
    user[sizeof(user)-1] = '\0';
    strncpy(appsrvid, appsrvid_buf, sizeof(appsrvid));
    appsrvid[sizeof(appsrvid)-1] = '\0';
    strncpy(appid, appid_buf, sizeof(appid));
    appsrvid[sizeof(appid)-1] = '\0';

    crypt_keyfile[sizeof(crypt_keyfile)-1] = '\0';
    cert_keyfile[sizeof(cert_keyfile)-1] = '\0';

    /* read in and initialize crypt and signing structures */
    c_stuff = libpbc_init_crypt(crypt_keyfile);
    ctx_plus = libpbc_sign_init(cert_keyfile);

    /* go get the cookie */
    cookie = libpbc_get_cookie(user, type, creds, serial, appsrvid, appid, ctx_plus, c_stuff);

    printf("%s", cookie);
    
    exit(0);

}
