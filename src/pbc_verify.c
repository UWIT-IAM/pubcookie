/*
    $Id: pbc_verify.c,v 1.7 1998-12-18 16:03:49 willey Exp $
 */

/*                                                                            */
/* args are: type                                                             */
/*                                                                            */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pem.h>
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

    if ( argc != 2 )
	exit(1);

    type = argv[1][0];
    if ( type == PBC_COOKIE_TYPE_G )
        ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);
    else if ( type == PBC_COOKIE_TYPE_L )
        ctx_plus = libpbc_verify_init(PBC_L_CERTFILE);
    else if ( type == PBC_COOKIE_TYPE_S )
        ctx_plus = libpbc_verify_init(PBC_S_CERTFILE);
    else
	exit (1);

    c_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    if( ! (cookie_data = libpbc_unbundle_cookie(in, ctx_plus, c_stuff)) )
	exit(1);

    printf("user: %s\n", (*cookie_data).broken.user);
    printf("version: %s\n", (*cookie_data).broken.version);
    printf("type: %c\n", (*cookie_data).broken.type);
    printf("creds: %c\n", (*cookie_data).broken.creds);
    printf("serial: %d\n", (*cookie_data).broken.serial);
    printf("appsrv_id: %s\n", (*cookie_data).broken.appsrv_id);
    printf("app_id: %s\n", (*cookie_data).broken.app_id);
    printf("create_ts: %d\n", (int)(*cookie_data).broken.create_ts);
    printf("last_ts: %d\n", (int)(*cookie_data).broken.last_ts);
    
    exit(0);

}
    
