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
    strcpy(in, "9043ddkljso2lkx90%lknxlwio2kxcvo;iw90dflkwekjvs98xcv,");

    fprintf(stderr, "in is %s\n", in);
    if ( ! libpbc_encrypt_cookie(in, intermediate, c1_stuff, strlen(in)) )
        exit(0);
    printf("%s", intermediate); 

    exit(1);

}
