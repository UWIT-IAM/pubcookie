/*
    $Id: pbc_create.c,v 1.3 1998-07-20 10:34:34 willey Exp $
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int main(int argc, char **argv) {
    md_context_plus *ctx_plus;
    unsigned char type;
    unsigned char creds;
    unsigned char appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char app_id[PBC_APP_ID_LEN];
    unsigned char *cookie;
    crypt_stuff         *c_stuff;
    FILE		*fp;

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
    c_stuff = libpbc_init_crypt();
    cookie = libpbc_get_cookie(argv[1], type, creds, appsrv_id, app_id, ctx_plus, c_stuff);

    fp = fopen("out", "w");
    if ( cookie ) {
	fprintf(fp, "%s", cookie);
	printf("%s\n", cookie);
    }
    fclose(fp);
    exit(0);

}

