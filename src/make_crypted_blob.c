
/*

    Copyright 1999-2001, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

 */

/*
    $Id: make_crypted_blob.c,v 1.1 2001-12-09 09:13:43 willey Exp $
 */


#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pem.h>
#include <unistd.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

void usage(const char *progname) {
    printf("%s [-o out_file] [-k key_file] [-h]\n\n", progname);
    printf("\t out_file:\twhere the output goes\n");
    printf("\t key_file:\tdefault is %s\n\n", PBC_CRYPT_KEYFILE);
    exit (1);
}

int main(int argc, char **argv) {
    crypt_stuff		*c1_stuff;
    unsigned char	in[PBC_1K];
    unsigned char	intermediate[PBC_1K];
    char		*key_file = NULL;
    char		*out_file = NULL;
    FILE		*ofp;
    int 		c, barfarg = 0;

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "ho:k:")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	case 'o' :
	    out_file = strdup(optarg);
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

    bzero(in, 1024);
    bzero(intermediate, 1024);
    strcpy(in, "Maybe this plaintext is another world's ciphertext.");

    fprintf(stderr, "ciphertext sent to stdout\n");
    if ( ! libpbc_encrypt_cookie(in, intermediate, c1_stuff, strlen(in)) )
        exit(0);

    if ( out_file ) {
        if( ! (ofp = pbc_fopen(out_file, "w")) )
            libpbc_abend("cannot open the out file %s\n", out_file);
    } else {
	ofp = stdout;
    }

    fprintf(ofp, "%s", intermediate); 

    exit(1);

}
