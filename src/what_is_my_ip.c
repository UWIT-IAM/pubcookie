/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file what_is_my_ip.c
 * Identifies IP being used by pubcookie
 *
 * $Id: what_is_my_ip.c,v 1.10 2004-02-10 00:42:15 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

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

/* openssl */
#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif /* HAVE_SYS_UTSNAME_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

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
