
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
    printf("%s -c crypted_file [-k key_file] [-h]\n\n", progname);
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

    bzero(in, 1024);
    bzero(out, 1024);
    bzero(intermediate, 1024);
    strcpy(in, "Maybe this plaintext is another world's ciphertext.");

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "hc:k:")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	case 'c' :
            if( crypted_file != NULL ) {
	        usage(argv[0]);
	        exit;
	    }
	    crypted_file = strdup(optarg);
	    break;
	case 'k' :
	    key_file = strdup(optarg);
	    break;
	default :
            if( crypted_file != NULL ) {
	        usage(argv[0]);
	        exit;
	    }
	    crypted_file = strdup(optarg);
	    break;
	}
    }

    if ( key_file )
        c1_stuff = libpbc_init_crypt(key_file);
    else
        c1_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    if ( c1_stuff == NULL ) {
	printf("unable to initialize encryption context\n");
        usage(argv[0]);
	exit;
    }

    if ( crypted_file != NULL ) {
        if( ! (cfp = pbc_fopen(crypted_file, "r")) )
            libpbc_abend("cannot open the crypted file %s\n", crypted_file);
        fread(intermediate, sizeof(char), PBC_1K, cfp);
    } else {
	printf("Must specify file with ciphertext\n\n");
	usage(argv[0]);
	exit;
    }

    if ( ! libpbc_decrypt_cookie(intermediate, out, c1_stuff, strlen(in)) )
        exit(0);
    printf("encrypted message is: %s\n", out);

    if( memcmp(in,out,sizeof(in)) != 0 )
	printf("cfb64 encrypt/decrypt error.\n");
    else
	printf("Yeah!  It worked\n");
    exit(1);

}
