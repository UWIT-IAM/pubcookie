#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pem.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

void *main() {
    crypt_stuff		*c1_stuff;
    unsigned char	in[1024];
    unsigned char	intermediate[1024];
    unsigned char	out[1024];


    c1_stuff = libpbc_init_crypt();

    bzero(in, 1024);
    bzero(out, 1024);
    bzero(intermediate, 1024);
    strcpy(in, "fasdfasdfsadfak2eiojslkdjf2io3erjlskdfjsdalkj asdfdf");

    printf("in is %s\n", in);
    libpbc_encrypt_cookie(in, intermediate, c1_stuff, strlen(in));
//    printf("intermediate out is %s\n", intermediate);
    libpbc_decrypt_cookie(intermediate, out, c1_stuff, strlen(in));
    printf("out is %s\n", out);

    if( memcmp(in,out,sizeof(in)) != 0 )
	printf("cfb64 encrypt/decrypt error\n");
    else
	printf("it worked\n");

    exit(1);

}
