/*
    $Id: candv.c,v 1.1 1998-07-15 00:21:22 willey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
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
    pbc_cookie_data	*cookie_data;

    md_context_plus 	*s_ctx_plus;
    md_context_plus	*v_ctx_plus;
    crypt_stuff         *c_stuff;

    // somethings for debugging
    type='1';
    creds='9';
    strcpy(appsrv_id, "appserver id is blah");
    strcpy(app_id, "application id is googoo");
    strcpy(user, "willey");

    c_stuff = libpbc_init_crypt();
    s_ctx_plus = libpbc_sign_init();
    v_ctx_plus = libpbc_verify_init();

    cookie = libpbc_get_cookie(user, type, creds, appsrv_id, app_id, s_ctx_plus, c_stuff);

//    v_ctx_plus = libpbc_verify_init();

    cookie_data = libpbc_unbundle_cookie(cookie, v_ctx_plus, c_stuff);

    if( cookie_data )
	printf("loser is %s\n", (*cookie_data).broken.user);
    else
	printf("I REALLY HATE life\n");

    exit(0);
}
    
