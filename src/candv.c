/*
    $Id: candv.c,v 1.3 1998-07-24 23:14:00 willey Exp $
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

int main(int argc, char **argv) {
    unsigned char type;
    unsigned char creds;
    char user[PBC_USER_LEN];
    unsigned char appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char app_id[PBC_APP_ID_LEN];
    unsigned char       *cookie;
    unsigned char       *updated_cookie;
    pbc_cookie_data	*cookie_data;
    pbc_cookie_data	*cookie_datax;
    pbc_cookie_data	*cookie_data2;

    md_context_plus 	*s_ctx_plus;
    md_context_plus	*v_ctx_plus;
    crypt_stuff         *c_stuff;

    type='1';
    creds='9';
    strncpy(appsrv_id, "appserver id is blah", PBC_APPSRV_ID_LEN);
    strncpy(app_id, "app id is googoo", PBC_APP_ID_LEN);
    strncpy(user, "bongo", PBC_USER_LEN);

    c_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);
    s_ctx_plus = libpbc_sign_init(PBC_G_KEYFILE);

    cookie = libpbc_get_cookie(user, type, creds, appsrv_id, app_id, s_ctx_plus, c_stuff);

    v_ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);

    printf("please wait while take a quick nap\n");
    sleep(2);

    cookie_data = libpbc_unbundle_cookie(cookie, v_ctx_plus, c_stuff);
    updated_cookie = libpbc_update_lastts(cookie_data, s_ctx_plus, c_stuff);

    cookie_datax = libpbc_unbundle_cookie(updated_cookie, v_ctx_plus, c_stuff);
    cookie_data2 = libpbc_unbundle_cookie(updated_cookie, v_ctx_plus, c_stuff);
    if( cookie_data2 ) {
	printf("loser is:\t>%s<\n", (*cookie_data2).broken.user);
	printf("version is:\t>%s<\n", (*cookie_data2).broken.version);
	printf("type is:\t>%c<\n", (*cookie_data2).broken.type);
	printf("cred is:\t>%c<\n", (*cookie_data2).broken.creds);
	printf("appsrv_id is:\t>%s<\n", (*cookie_data2).broken.appsrv_id);
	printf("app_id is:\t>%s<\n", (*cookie_data2).broken.app_id);
	printf("create is:\t>%s<\n", libpbc_time_string((*cookie_data2).broken.create_ts));
	printf("last is:\t>%s<\n", libpbc_time_string((*cookie_data2).broken.last_ts));
    } 
    else {
	printf("this sucks\n");
    } 

    exit(0);
}
    
