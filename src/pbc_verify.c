/*
    $Id: pbc_verify.c,v 1.3 1998-07-20 10:34:34 willey Exp $
 */


#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pbc_config.h"
#include "pubcookie.h"
#include "libpubcookie.h"
/* #include <envelope.h> */

int main(int argc, char **argv) {
    char buf[4096];
    char *cookie = buf + PBC_SIG_LEN;
    md_context_plus	*ctx_plus;
    pbc_cookie_data	*cookie_data;
    FILE		*fp;
    char		in[4096];
    crypt_stuff         *c_stuff;

    memset(buf, 0, sizeof(buf));

    fp = fopen("out", "r");
    fgets(in, 4096, fp);
    fclose(fp);

//    if(argc != 2) {
//        fprintf(stderr, "usage: %s cookie\n", argv[0]);
//        exit(1);
//    }

//    if(strlen(argv[1]) > 512) {
//        fprintf(stderr, "Cookie is too long.\n");
//        exit(1);
//    }

    ctx_plus = libpbc_verify_init();
    c_stuff = libpbc_init_crypt();
//    if( ! (cookie_data = libpbc_unbundle_cookie(argv[1], ctx_plus)) ) {
    if( ! (cookie_data = libpbc_unbundle_cookie(in, ctx_plus, c_stuff)) ) {
	fprintf(stderr, "Could not verify signature.\n");
	exit(1);
    }

    printf("user is >%s<\n", (*cookie_data).broken.user);
    printf("app_id is >%s<\n", (*cookie_data).broken.app_id);
    printf("%s\n", cookie);
    exit(0);
}
    
