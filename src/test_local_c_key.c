#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

void usage(const char *progname) {
    printf("%s [-c crypted_file] [-k key_file] [-h]\n\n", progname);
    printf("\t crypted_file:       crypted stuff to be decrypted, should not be necessary since the binary will already have it.\n");
    printf("\t key_file:  default is %s\n\n", PBC_CRYPT_KEYFILE);
    exit (1);
}

int main(int argc, char **argv) {
    crypt_stuff		*c1_stuff;
    unsigned char	in[PBC_1K];
    unsigned char	intermediate[PBC_1K];
    unsigned char	out[PBC_1K];
    FILE		*cfp;
    int 		c, barfarg = 0;
    char		*key_file = NULL;
    char		*crypted_file = NULL;
    static unsigned char c_bits[]={
        0x7e,0x8e,0x69,0x0d,0x49,0x87,0x14,0xec,
        0xad,0xf3,0xdb,0x1b,0xc2,0x9e,0x50,0xb4,
        0xd3,0xab,0x2d,0x78,0x51,0xd6,0x1a,0x4d,
        0x98,0xad,0xf6,0x30,0x62,0x1f,0xac,0x1a,
        0x43,0x89,0xe3,0x96,0x19,0x32,0xf3,0xb1,
        0xd7,0xd5,0xa1,0x23,0x2e,0x51,0xc2,0x26,
        0xb8,0x7b,0x61,0xe3,0x54,0x44,0xee,
    };

    bzero(in, 1024);
    bzero(out, 1024);
    bzero(intermediate, 1024);
    strcpy(in, "9043ddkljso2lkx90%lknxlwio2kxcvo;iw90dflkwekjvs98xcv,");

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "hc:k:")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	case 'c' :
	    crypted_file = strdup(optarg);
	    break;
	case 'k' :
	    key_file = strdup(optarg);
	    break;
	default :
	    barfarg++;
	    usage(argv[0]);
	}
    }

    if ( key_file )
        c1_stuff = libpbc_init_crypt(key_file);
    else
        c1_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    if ( crypted_file ) {
        if( ! (cfp = pbc_fopen(crypted_file, "r")) )
            libpbc_abend("cannot open the crypted file %s\n", crypted_file);
        fread(intermediate, sizeof(char), PBC_1K, cfp);
    } else {
	memcpy(intermediate, c_bits, PBC_1K);
    }

    if ( ! libpbc_decrypt_cookie(intermediate, out, c1_stuff, strlen(in)) )
        exit(0);
    printf("out is %s\n", out);

    if( memcmp(in,out,sizeof(in)) != 0 )
	printf("cfb64 encrypt/decrypt error\n");
    else
	printf("it worked\n");

    exit(1);

}
