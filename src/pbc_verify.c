/*
    $Id: pbc_verify.c,v 1.1 1998-06-25 03:00:58 willey Exp $
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
    context_plus	*ctx_plus;
    pbc_cookie_data	*cookie_data;

    memset(buf, 0, sizeof(buf));

    if(argc != 2) {
        fprintf(stderr, "usage: %s cookie\n", argv[0]);
        exit(1);
    }

    if(strlen(argv[1]) > 512) {
        fprintf(stderr, "Cookie is too long.\n");
        exit(1);
    }

    ctx_plus = libpbc_verify_init();
    if( ! (cookie_data = libpbc_unbundle_cookie(argv[1], ctx_plus)) ) {
	fprintf(stderr, "Could not verify signature.\n");
	exit(1);
    }

    printf("%s\n", cookie);
    exit(0);
}
    
