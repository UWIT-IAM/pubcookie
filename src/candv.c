/*
    $Id: candv.c,v 1.9 1999-02-10 19:52:33 willey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include <unistd.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

void usage(const char *progname) {
    printf("%s [-k key_file] [-c cert_file] [-s key_for_cert_file][-h]\n\n", progname);
    printf("\t key_file:\tencyption key, \n\t\t\tdefault is %s\n", PBC_CRYPT_KEYFILE);
    printf("\t cert_file:\tcetificate file, \n\t\t\tdefault is %s\n", PBC_G_CERTFILE);
    printf("\t key_for_cert_file:\tkey for cetificate file, \n\t\t\tdefault is %s\n\n", PBC_G_KEYFILE);
    exit (1);
}

int main(int argc, char **argv) {
    unsigned char type;
    unsigned char creds;
    int serial=2147483647;
    char user[PBC_USER_LEN];
    unsigned char appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char app_id[PBC_APP_ID_LEN];
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
    strncpy(appsrv_id, "appserver id is blah", PBC_APPSRV_ID_LEN);
    strncpy(app_id, "app id is googoo", PBC_APP_ID_LEN);
    strncpy(user, "bongo", PBC_USER_LEN);

    if ( key_file )
        c_stuff = libpbc_init_crypt(key_file);
    else
        c_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    if ( g_key_file )
        s_ctx_plus = libpbc_sign_init(g_key_file);
    else
        s_ctx_plus = libpbc_sign_init(PBC_G_KEYFILE);

    if ( g_cert_file )
        v_ctx_plus = libpbc_verify_init(g_cert_file);
    else
        v_ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);

    printf("cook up a cookie\n");
    cookie = libpbc_get_cookie(user, type, creds, serial, appsrv_id, app_id, s_ctx_plus, c_stuff);

    printf("please wait while take a quick nap\n");
    sleep(2);

    if ( ! (cookie_data=libpbc_unbundle_cookie(cookie, v_ctx_plus, c_stuff)) ) {
        printf("test failed: cookie couldn't be unbundled\n");
	exit (1);
    }
    printf("update that cookie\n");
    updated_cookie = libpbc_update_lastts(cookie_data, s_ctx_plus, c_stuff);

    printf("verify and show me the cookie\n");
    cookie_data2 = libpbc_unbundle_cookie(updated_cookie, v_ctx_plus, c_stuff);
    if( cookie_data2 ) {
	printf("loser is:\t>%s<\n", (*cookie_data2).broken.user);
	printf("version is:\t>%s<\n", (*cookie_data2).broken.version);
	printf("type is:\t>%c<\n", (*cookie_data2).broken.type);
	printf("cred is:\t>%c<\n", (*cookie_data2).broken.creds);
	printf("serial is:\t>%d<\n", (*cookie_data2).broken.serial);
	printf("appsrv_id is:\t>%s<\n", (*cookie_data2).broken.appsrv_id);
	printf("app_id is:\t>%s<\n", (*cookie_data2).broken.app_id);
	printf("create is:\t>%s<\n", libpbc_time_string((*cookie_data2).broken.create_ts));
	printf("last is:\t>%s<\n", libpbc_time_string((*cookie_data2).broken.last_ts));
    } 
    else {
	printf("this sucks\n");
    } 

    printf("cook up another cookie\n");
    cookie = libpbc_get_cookie(user, type, creds, serial, appsrv_id, app_id, s_ctx_plus, c_stuff);

    printf("please wait while take a quick nap\n");
    sleep(2);

    printf("verify and show me the cookie\n");
    if ( ! (cookie_data=libpbc_unbundle_cookie(cookie, v_ctx_plus, c_stuff)) ) {
	printf("test failed: cookie couldn't be unbundled\n");
        exit (1);
    }

    if( cookie_data ) {
	printf("loser is:\t>%s<\n", (*cookie_data).broken.user);
	printf("version is:\t>%s<\n", (*cookie_data).broken.version);
	printf("type is:\t>%c<\n", (*cookie_data).broken.type);
	printf("cred is:\t>%c<\n", (*cookie_data).broken.creds);
	printf("serial is:\t>%d<\n", (*cookie_data).broken.serial);
	printf("appsrv_id is:\t>%s<\n", (*cookie_data).broken.appsrv_id);
	printf("app_id is:\t>%s<\n", (*cookie_data).broken.app_id);
	printf("create is:\t>%s<\n", libpbc_time_string((*cookie_data).broken.create_ts));
	printf("last is:\t>%s<\n", libpbc_time_string((*cookie_data).broken.last_ts));
    } 
    else {
	printf("this sucks\n");
    } 
    exit(0);
}
    
