/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_verify.c
 * Manually verify cookies
 *
 * args are:
 *   cookie_type [encryption_key] [cert_file]
 *      if you specify a cert_file you must also specifiy a crypt key
 *
 * cookie comes in on stdin, contenets are printed to stdout
 *
 * $Id: pbc_verify.c,v 1.17 2003-07-02 22:04:04 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

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

#include "pbc_config.h"
#include "pubcookie.h"
#include "libpubcookie.h"

int main(int argc, char **argv) {
    md_context_plus	*ctx_plus;
    crypt_stuff         *c_stuff;
    pbc_cookie_data	*cookie_data;
    char		in[PBC_4K];
    unsigned char       type;

    fgets(in, sizeof(in), stdin);

    if ( argc < 2 )
	exit(1);

    type = argv[1][0];

    /* if we're given a keyfile, use it */
    if ( argv[2] )
        c_stuff = libpbc_init_crypt(argv[2]);
    else
        c_stuff = libpbc_init_crypt(get_my_hostname());


    /* if we're given a certfile to use, use it */
    if ( argv[2] && argv[3] )
        ctx_plus = libpbc_verify_init(argv[3]);
    else if ( type == PBC_COOKIE_TYPE_G )
        ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);
    else if ( type == PBC_COOKIE_TYPE_L )
        ctx_plus = libpbc_verify_init(PBC_S_CERTFILE);
    else if ( type == PBC_COOKIE_TYPE_S )
        ctx_plus = libpbc_verify_init(PBC_S_CERTFILE);
    else
	exit (1);

    if( ! (cookie_data = libpbc_unbundle_cookie(in, ctx_plus, c_stuff)) )
	exit(1);

    printf("user: %s\n", (*cookie_data).broken.user);
    printf("version: %s\n", (*cookie_data).broken.version);
    printf("type: %c\n", (*cookie_data).broken.type);
    printf("creds: %c\n", (*cookie_data).broken.creds);
    printf("pre_sess_token: %d\n", (*cookie_data).broken.pre_sess_token);
    printf("appsrvid: %s\n", (*cookie_data).broken.appsrvid);
    printf("appid: %s\n", (*cookie_data).broken.appid);
    printf("create_ts: %d\n", (int)(*cookie_data).broken.create_ts);
    printf("last_ts: %d\n", (int)(*cookie_data).broken.last_ts);
    
    exit(0);

}
