/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: candv.c,v 1.22 2004-02-10 00:42:14 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

void usage(const char *progname) {
    printf("%s [-k key_file] [-c cert_file] [-s key_for_cert_file][-h]\n\n", progname);
    printf("\t key_file:\tencyption key, \n\t\t\tdefault is %s/HOSTNAME\n", PBC_PATH);
    printf("\t cert_file:\tcetificate file, \n\t\t\tdefault is %s\n", PBC_G_CERTFILE);
    printf("\t key_for_cert_file:\tkey for cetificate file, \n\t\t\tdefault is %s\n\n", PBC_G_KEYFILE);
    exit (1);
}

int main(int argc, char **argv) {
    unsigned char type;
    unsigned char creds;
    int pre_sess_token=2147483647;
    char user[PBC_USER_LEN];
    unsigned char appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char appid[PBC_APP_ID_LEN];
    unsigned char       *cookie;
    unsigned char       *updated_cookie;
    pbc_cookie_data	*cookie_data;
    pbc_cookie_data	*cookie_data2;
    char		*key_file = NULL;
    char		*g_cert_file = NULL;
    char		*g_key_file = NULL;
    int 		c, barfarg = 0;

    md_context_plus 	*s_ctx_plus;
    md_context_plus	*v_ctx_plus;
    crypt_stuff         *c_stuff;

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "hk:c:s:")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	case 'k' :
	    key_file = strdup(optarg);
	    break;
	case 'c' :
	    g_cert_file = strdup(optarg);
	    break;
	case 's' :
	    g_key_file = strdup(optarg);
	    break;
	default :
	    barfarg++;
	    usage(argv[0]);
	}
    }

    type='1';
    creds='9';
    strncpy( (char *) appsrvid, "appserver id is blah", PBC_APPSRV_ID_LEN);
    strncpy( (char *) appid, "app id is googoo", PBC_APP_ID_LEN);
    strncpy(user, "bongo", PBC_USER_LEN);

    if ( key_file )
        c_stuff = libpbc_init_crypt(key_file);
    else
        c_stuff = libpbc_init_crypt(get_my_hostname());

    if ( g_key_file )
        s_ctx_plus = libpbc_sign_init(g_key_file);
    else
        s_ctx_plus = libpbc_sign_init(PBC_G_KEYFILE);

    if ( g_cert_file )
        v_ctx_plus = libpbc_verify_init(g_cert_file);
    else
        v_ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);

    printf("cook up a cookie\n");
    cookie = libpbc_get_cookie( (unsigned char *) user, type, creds, pre_sess_token, appsrvid, appid, s_ctx_plus, c_stuff);

    if ( ! (cookie_data=libpbc_unbundle_cookie( (char *) cookie, v_ctx_plus, c_stuff)) ) {
        printf("test failed: cookie couldn't be unbundled\n");
        exit (1);
    }
    printf("update that cookie\n");
    updated_cookie = libpbc_update_lastts(cookie_data, s_ctx_plus, c_stuff);

    printf("verify and show me the cookie\n");
    cookie_data2 = libpbc_unbundle_cookie( (char *) updated_cookie, v_ctx_plus, c_stuff);
    if( cookie_data2 ) {
	printf("loser is:\t>%s<\n", (*cookie_data2).broken.user);
	printf("version is:\t>%s<\n", (*cookie_data2).broken.version);
	printf("type is:\t>%c<\n", (*cookie_data2).broken.type);
	printf("cred is:\t>%c<\n", (*cookie_data2).broken.creds);
	printf("pre_sess_token is:\t>%d<\n", (*cookie_data2).broken.pre_sess_token);
	printf("appsrvid is:\t>%s<\n", (*cookie_data2).broken.appsrvid);
	printf("appid is:\t>%s<\n", (*cookie_data2).broken.appid);
	printf("create is:\t>%s<\n", libpbc_time_string((*cookie_data2).broken.create_ts));
	printf("last is:\t>%s<\n", libpbc_time_string((*cookie_data2).broken.last_ts));
    } 
    else {
	printf("this sucks\n");
    } 

    printf("cook up another cookie\n");
    cookie = libpbc_get_cookie( (unsigned char *) user, type, creds, pre_sess_token, appsrvid, appid, s_ctx_plus, c_stuff);

    printf("verify and show me the cookie\n");
    if ( ! (cookie_data=libpbc_unbundle_cookie( (char *) cookie, v_ctx_plus, c_stuff)) ) {
	printf("test failed: cookie couldn't be unbundled\n");
        exit (1);
    }

    if( cookie_data ) {
	printf("loser is:\t>%s<\n", (*cookie_data).broken.user);
	printf("version is:\t>%s<\n", (*cookie_data).broken.version);
	printf("type is:\t>%c<\n", (*cookie_data).broken.type);
	printf("cred is:\t>%c<\n", (*cookie_data).broken.creds);
	printf("pre_sess_token is:\t>%d<\n", (*cookie_data).broken.pre_sess_token);
	printf("appsrvid is:\t>%s<\n", (*cookie_data).broken.appsrvid);
	printf("appid is:\t>%s<\n", (*cookie_data).broken.appid);
	printf("create is:\t>%s<\n", libpbc_time_string((*cookie_data).broken.create_ts));
	printf("last is:\t>%s<\n", libpbc_time_string((*cookie_data).broken.last_ts));
    } 
    else {
	printf("this sucks\n");
    } 
    exit(0);
}
    
