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

    c1_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    bzero(in, 1024);
    bzero(intermediate, 1024);
    strcpy(in, "fasdfasdfsadfak2eiojslkdjf2io3erjlskdfjsdalkj asdfdf");

    fprintf(stderr, "in is %s\n", in);
    if ( ! libpbc_encrypt_cookie(in, intermediate, c1_stuff, strlen(in)) )
        exit(0);
    printf("%s", intermediate); 

    exit(1);

}
