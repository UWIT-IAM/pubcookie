/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_key_local.c
 * Old (and i think obsolete) key mgmt
 *
 * $Id: pbc_key_local.c,v 1.13 2004-12-22 22:14:54 willey Exp $
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

void usage (const char *progname)
{
    printf ("%s -a ip [-o out_keyfile] [-i master_keyfile] [-h]\n\n",
            progname);
    printf ("\t ip:              numbers-and-dots notation\n");
    printf ("\t master_keyfile:  master keyfile, default is %s\n",
            PBC_MASTER_CRYPT_KEYFILE);
    printf ("\t out_keyfile:     new keyfile, default is stdout\n\n");
    exit (1);
}

char *libpbc_mod_crypt_key (char *in, unsigned char *addr_bytes)
{
    int i;

    for (i = 0; i < PBC_DES_KEY_BUF; ++i) {
        in[i] ^= addr_bytes[i % 4];
    }
}

int main (int argc, char **argv)
{
    unsigned char *key_buf;
    unsigned long int addr;
    unsigned char *addr_s;
    FILE *ifp;
    FILE *ofp;
    char *out_file = NULL;
    char *in_file = NULL;
    char *ip = NULL;
    int c, barfarg = 0;

    optarg = NULL;
    while (!barfarg && ((c = getopt (argc, argv, "ha:o:i:")) != -1)) {
        switch (c) {
        case 'h':
            usage (argv[0]);
            break;
        case 'o':
            out_file = strdup (optarg);
            break;
        case 'i':
            in_file = strdup (optarg);
            break;
        case 'a':
            ip = strdup (optarg);
            break;
        default:
            barfarg++;
            usage (argv[0]);
        }
    }

    if (!ip) {
        printf ("\nMust specifiy IP\n");
        usage (argv[0]);
    }

    if (in_file) {
        if (!(ifp = pbc_fopen (in_file, "r")))
            libpbc_abend ("cannot open the input key file %s for read\n",
                          in_file);
    } else {
        if (!(ifp = pbc_fopen (PBC_MASTER_CRYPT_KEYFILE, "r")))
            libpbc_abend ("make localized crypt key: Failed open %s\n",
                          PBC_MASTER_CRYPT_KEYFILE);
    }

    if (out_file) {
        if (!(ofp = pbc_fopen (out_file, "w")))
            libpbc_abend
                ("cannot open the output key file %s for writing\n",
                 out_file);
    } else {
        ofp = stdout;
    }

    key_buf = (unsigned char *) libpbc_alloc_init (PBC_DES_KEY_BUF);
    addr_s = (unsigned char *) libpbc_alloc_init (sizeof (addr));

    if (fread (key_buf, sizeof (char), PBC_DES_KEY_BUF, ifp) !=
        PBC_DES_KEY_BUF)
        libpbc_abend ("make localized crypt key: Failed read\n");

    addr = inet_addr (ip);
    memcpy (addr_s, &addr, sizeof (addr));

    key_buf =
        (unsigned char *) libpbc_mod_crypt_key ((char *) key_buf, addr_s);

    if (fwrite (key_buf, sizeof (char), PBC_DES_KEY_BUF, ofp) !=
        PBC_DES_KEY_BUF)
        libpbc_abend ("libpbc_crypt_key: Failed write\n");

    exit (0);

}
