/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: make_crypted_blob.c,v 1.9 2004-02-10 00:42:15 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#if !defined(WIN32)
# ifdef HAVE_NETDB_H
#  include <netdb.h>
# endif /* HAVE_NETDB_H */
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#if defined (WIN32) 
# include <winsock2.h>   // jimb - WSASTARTUP for gethostname
# include <getopt.h>     // jimb - getopt from pdtools
extern char * optarg;
# define bzero(s,n) memset((s),0,(n))  // jimb - win32
#else /* WIN32 */

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif /* HAVE_UNISTD_H */

# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# endif /* HAVE_SYS_SOCKET_H */

# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif /* HAVE_NETINET_IN_H */

# ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
# endif /* HAVE_ARPA_INET_H */

#endif /* WIN32 */

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
    printf("\t c_key_file:\tdefault is %s/%d\n\n", PBC_PATH, get_my_hostname());
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
        sprintf(key_file,"%s/%s",PBC_PATH, get_my_hostname());
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
