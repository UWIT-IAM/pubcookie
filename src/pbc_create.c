/*
    $Id: pbc_create.c,v 1.5 1998-07-28 23:03:57 willey Exp $
 */

/* this is not meant to be user friendly, no friendlyness for anyone          */
/*   but me and i have the src code                                           */
/*                                                                            */
/* args are: user appsrv_id app_id type creds                                 */
/*    (anything too big is just truncated)                                    */
/*                                                                            */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int main(int argc, char **argv) {
    md_context_plus 	*ctx_plus;
    crypt_stuff         *c_stuff;

    unsigned char 	user[PBC_USER_LEN];
    unsigned char 	appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char 	app_id[PBC_APP_ID_LEN];
    unsigned char 	type;
    unsigned char 	creds;

    unsigned char 	*cookie;

    if(argc != 6)
        exit(1);

    strncpy(user, argv[1], sizeof(user));
    user[sizeof(user)-1] = '\0';
    strncpy(appsrv_id, argv[2], sizeof(appsrv_id));
    appsrv_id[sizeof(appsrv_id)-1] = '\0';
    strncpy(app_id, argv[3], sizeof(app_id));
    appsrv_id[sizeof(app_id)-1] = '\0';
    type = argv[4][0];
    creds = argv[5][0];

    if ( type == PBC_COOKIE_TYPE_G ) 
        ctx_plus = libpbc_sign_init(PBC_G_KEYFILE);
    else if ( type == PBC_COOKIE_TYPE_L ) 
        ctx_plus = libpbc_sign_init(PBC_L_KEYFILE);
    else if ( type == PBC_COOKIE_TYPE_S ) 
        ctx_plus = libpbc_sign_init(PBC_S_KEYFILE);
    else
        exit(1);

    c_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    cookie = libpbc_get_cookie(user, type, creds, appsrv_id, app_id, ctx_plus, c_stuff);

    printf("%s", cookie);
    
    exit(0);

}

