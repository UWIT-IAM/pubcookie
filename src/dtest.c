/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
  $Id: dtest.c,v 1.18 2004-12-22 22:14:54 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

void usage (const char *progname)
{
    printf ("%s [-k key_file] [-h]\n\n", progname);
    printf ("\t key_file:\tdefault is %s/%s\n\n", PBC_PATH,
            get_my_hostname ());
    exit (1);
}

int main (int argc, char **argv)
{
    char *key_file = NULL;
    int c, barfarg = 0;
    crypt_stuff *c1_stuff;
    unsigned char in[PBC_1K];
    unsigned char intermediate[PBC_1K];
    unsigned char out[PBC_1K];

    optarg = NULL;
    while (!barfarg && ((c = getopt (argc, argv, "hk:")) != -1)) {
        switch (c) {
        case 'h':
            usage (argv[0]);
            break;
        case 'k':
            key_file = strdup (optarg);
            break;
        default:
            barfarg++;
            usage (argv[0]);
        }
    }

    if (key_file)
        c1_stuff = libpbc_init_crypt (key_file);
    else
        c1_stuff = libpbc_init_crypt (get_my_hostname);

    bzero (in, 1024);
    bzero (out, 1024);
    bzero (intermediate, 1024);
    strcpy ((char *) in,
            "fasdfasdfsadfak2eiojslkdjf2io3erjlskdfjsdalkj asdfdf");

    printf ("in is %s\n", in);
    if (!libpbc_encrypt_cookie
        (in, intermediate, c1_stuff, strlen ((char *) in)))
        exit (0);
/*    printf("intermediate out is %s\n", intermediate); */
    if (!libpbc_decrypt_cookie
        (intermediate, out, c1_stuff, strlen ((char *) in)))
        exit (0);
    printf ("out is %s\n", out);

    if (memcmp (in, out, sizeof (in)) != 0)
        printf ("cfb64 encrypt/decrypt error the fist time\n");
    else
        printf ("it the first time worked\n");

    printf ("in is %s\n", in);
    if (!libpbc_encrypt_cookie
        (in, intermediate, c1_stuff, strlen ((char *) in)))
        exit (0);
/*    printf("intermediate out is %s\n", intermediate); */
    if (!libpbc_decrypt_cookie
        (intermediate, out, c1_stuff, strlen ((char *) in)))
        exit (0);
    printf ("out is %s\n", out);

    if (memcmp (in, out, sizeof (in)) != 0)
        printf ("cfb64 encrypt/decrypt error the second time\n");
    else
        printf ("it worked the second time\n");

    exit (1);

}
