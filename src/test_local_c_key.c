#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pem.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int *main() {
    crypt_stuff		*c1_stuff;
    unsigned char	in[PBC_1K];
    unsigned char	intermediate[PBC_1K];
    unsigned char	out[PBC_1K];

    c1_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    bzero(in, 1024);
    bzero(out, 1024);
    bzero(intermediate, 1024);
    strcpy(in, "fasdfasdfsadfak2eiojslkdjf2io3erjlskdfjsdalkj asdfdf");

    fread(intermediate, sizeof(char), PBC_1K, stdin);

    if ( ! libpbc_decrypt_cookie(intermediate, out, c1_stuff, strlen(in)) )
        exit(0);
    printf("out is %s\n", out);

    if( memcmp(in,out,sizeof(in)) != 0 )
	printf("cfb64 encrypt/decrypt error\n");
    else
	printf("it worked\n");

    exit(1);

}
