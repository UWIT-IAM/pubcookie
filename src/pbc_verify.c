/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_verify.c
 * Manually verify cookies
 *
 * args are:
 *   granting_or_no [encryption_key] [cert_file]
 *      if you specify a cert_file you must also specifiy a crypt key
 *
 * granting or no is 1 for granting or 0 for no
 *
 * cookie comes in on stdin, contenets are printed to stdout
 *
 * $Id: pbc_verify.c,v 1.19 2004-10-07 08:35:45 willey Exp $
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

/* An apache "pool" */
typedef void pool;

#include "pbc_config.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_configure.h"
#include "pbc_version.h"
#include "pbc_logging.h"


int main(int argc, char **argv) {
    md_context_plus	*ctx_plus;
    crypt_stuff         *c_stuff;
    pbc_cookie_data	*cookie_data;
    char		in[PBC_4K];
    char 		*s;
    void 		*p = NULL;
    security_context 	*context = NULL;
    int			use_granting = 0;
    

    fgets(in, sizeof(in), stdin);

    s = in;
    while(*s) {
        if( *s == '\r' || *s == '\n' ) {
            *s = '\0';
             break;
        }
        s++;
    }
/*
    if ( argc < 2 )
	exit(1);
 */

    use_granting = argv[1][0];

    libpbc_config_init(p, NULL, "pbc_verify");
    pbc_log_init_syslog(p, "pbc_verifyr");
    libpbc_pubcookie_init(p, &context);

    if( ! (cookie_data = libpbc_unbundle_cookie(p, context, in, NULL, use_granting)) )
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
