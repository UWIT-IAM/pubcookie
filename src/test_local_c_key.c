
/* Copyright 1999, University of Washington.  All rights reserved. */

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
        0xce, 0x64, 0x96, 0xf6, 0xc7, 0x21, 0xe6, 0x41, 
        0x79, 0x60, 0xd1, 0x06, 0x58, 0xad, 0x42, 0x59,
        0xcb, 0x71, 0x14, 0x57, 0x27, 0x17, 0x07, 0xfe, 
        0xce, 0xb8, 0x6e, 0x69, 0x09, 0x0d, 0x3d, 0x1f,
        0xf8, 0xfa, 0x28, 0xc6, 0x07, 0x99, 0x12, 0x6c, 
        0x79, 0x70, 0x51, 0x54, 0xc7, 0x64, 0x34, 0x3f,
        0x88, 0xd0, 0x92, 0x59, 0x18, 0x4e, 0xe0,
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

