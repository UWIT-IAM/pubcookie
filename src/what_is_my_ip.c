

/* Copyright 1999-2001, University of Washington.  All rights reserved. */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

void usage(const char *progname) {
    printf("%s [-h]\n\n", progname);
    exit (1);

}

int main(int argc, char **argv) {
    int 		c;
    int			barfarg = 0;
    int 		i = 0;
    struct utsname      myname;
    struct hostent      *h;
    unsigned char       *addr;

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "h")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	default :
	    barfarg++;
	    usage(argv[0]);
	}
    }

    if ( uname(&myname) < 0 ) {
        printf("problem doing uname lookup\n");
        exit(0);
    }
    printf("myname.nodename: %s\n", myname.nodename);

/*    printf("ip: %s\n", inet_ntoa((struct in_addr)libpbc_gethostip())); */
    printf("libpubcookie calls: ip: %d-%d-%d-%d\n", libpbc_gethostip()[0],
                                libpbc_gethostip()[1],
                                libpbc_gethostip()[2],
                                libpbc_gethostip()[3]);


    if ( (h = gethostbyname(myname.nodename)) == NULL ) {
        printf("%s: host unknown.\n", myname.nodename);
        exit(0);
    }

    while( h->h_addr_list[i] != 0 ) {
        addr = libpbc_alloc_init(h->h_length);
        memcpy(addr, h->h_addr_list[i], h->h_length);

        printf("Address %d: %d-%d-%d-%d\n", i++, addr[0],
						 addr[1],
						 addr[2],
						 addr[3]);
    }

    exit(1);
}
