/*

    Copyright 1999-2002, University of Washington.  All rights reserved.

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
    $Id: make_crypted_blob.c,v 1.4 2002-06-03 20:50:01 jjminer Exp $
 */


#if !defined(WIN32)
#include <netdb.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#if defined (WIN32) 
#include <winsock2.h>   // jimb - WSASTARTUP for gethostname
#include <getopt.h>     // jimb - getopt from pdtools
extern char * optarg;
#define bzero(s,n)	memset((s),0,(n))  // jimb - win32
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

#if defined (WIN32)
extern int Debug_Trace = 0;
extern FILE *debugFile = NULL;
#endif

void usage(const char *progname) {
    printf("%s [-o out_file] [-k c_key_file] [-h]\n\n", progname);
    printf("\t out_file:\twhere the output goes\n");
    printf("\t c_key_file:\tdefault is %s\n\n", PBC_CRYPT_KEYFILE);
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
#if defined (WIN32)
    char		SystemRoot[256];

    Debug_Trace = 1;
    debugFile = stderr;
#endif

    fprintf(stderr,"make_crypted_blob\n\n");

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

#if defined(WIN32)                                           
	{   
	WSADATA wsaData;

	if( WSAStartup((WORD)0x0101, &wsaData ) ) 
	{  
	    fprintf(stderr,"Unable to initialize WINSOCK: %d", WSAGetLastError() );
	    return -1;
	}
	}   
#endif

    if ( key_file )
        c1_stuff = libpbc_init_crypt(key_file);
    else {
	key_file = malloc(256);
#if defined(WIN32)  
	GetEnvironmentVariable ("windir",SystemRoot,256);
        sprintf(key_file,"%s%s", SystemRoot,PBC_CRYPT_KEYFILE);
#else
        sprintf(key_file,"%s",PBC_CRYPT_KEYFILE);
#endif
	fprintf(stderr,"Using c_key file: %s\n\n",key_file);
        c1_stuff = libpbc_init_crypt(key_file);
	}

    bzero(in, 1024);
    bzero(intermediate, 1024);
    strcpy( (char *) in, "Maybe this plaintext is another world's ciphertext.");

    
    if ( ! libpbc_encrypt_cookie(in, intermediate, c1_stuff, strlen( (char *) in)) ) {
        printf("\n*** Libpbc_encrypt_cookie failed\n");
        exit(1);
    }

    if ( out_file ) {
	fprintf(stderr, "\nciphertext sent to %s\n\n",out_file);
	if( ! (ofp = pbc_fopen(out_file, "w")) ) {
            libpbc_abend("\n*** Cannot open the out file %s\n", out_file);
	    exit(1);
	}
    } else {
	fprintf(stderr, "\nciphertext sent to stdout\n\n");
	ofp = stdout;
    }

    fprintf(ofp, "%s", intermediate); 

#if defined(WIN32)  
    WSACleanup();
#endif

    exit(0);

}
