/*
    $Id: pbc_create.c,v 1.1 1998-06-25 03:00:58 willey Exp $
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int main(int argc, char **argv) {
    context_plus *ctx_plus;
    char type;
    char creds;
    char appsrv_id[PBC_APPSRV_ID_LEN];
    char app_id[PBC_APP_ID_LEN];
    char *cookie;

    // somethings for debugging
    type='1';
    creds='9';
    strcpy(appsrv_id, "appserver id is blah");
    strcpy(app_id, "application id is googoo");

    if(argc != 2) {
        fprintf(stderr, "usage: %s username\n", argv[0]);
        exit(1);
    }

    if(strlen(argv[1]) > 256) {
        fprintf(stderr, "Username is too long.\n");
        exit(1);
    }

    ctx_plus = libpbc_sign_init();
    cookie = libpbc_get_cookie(argv[1], type, creds, appsrv_id, app_id, ctx_plus);

    if ( cookie ) 
	printf("%s\n", cookie);
    exit(0);

}

