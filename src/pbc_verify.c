/*
    $Id: pbc_verify.c,v 1.4 1998-07-24 23:14:00 willey Exp $
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pbc_config.h"
#include "pubcookie.h"
#include "libpubcookie.h"

int main(int argc, char **argv) {
    char 		buf[PBC_4K];
    md_context_plus	*ctx_plus;
    pbc_cookie_data	*cookie_data;
    FILE		*fp;
    char		in[PBC_4K];
    crypt_stuff         *c_stuff;

    memset(buf, 0, sizeof(buf));

    fp = fopen("out", "r");
    fgets(in, sizeof(in), fp);
    fclose(fp);

    ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);
    c_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);
    if( ! (cookie_data = libpbc_unbundle_cookie(in, ctx_plus, c_stuff)) ) {
	fprintf(stderr, "Could not verify signature.\n");
	exit(1);
    }

    printf("user is >%s<\n", (*cookie_data).broken.user);
    printf("app_id is >%s<\n", (*cookie_data).broken.app_id);
    exit(0);

}
    
