/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file verify.c
 * Verifier base stuff
 *
 * $Id: verify.c,v 1.23 2004-02-16 17:05:31 jteaton Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

/* Pretending we're Apache */
typedef void pool;

#include "verify.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/* verifiers we might have access to */
extern verifier kerberos4_verifier;
extern verifier kerberos5_verifier;
extern verifier ldap_verifier;
extern verifier alwaystrue_verifier;
extern verifier shadow_verifier;
extern verifier fork_verifier;
extern verifier uwsecurid_verifier;

/* verifiers that we actually compiled */
static verifier *verifiers[] = {
    &kerberos4_verifier,
    &kerberos5_verifier,
    &ldap_verifier,
    &alwaystrue_verifier,
    &shadow_verifier,
    &fork_verifier,
    &uwsecurid_verifier,
    NULL
};

/* given a string, find the corresponding verifier */
verifier *get_verifier(const char *name)
{
    verifier **v = verifiers;
    while (*v) {
	if (!strcasecmp((*v)->name, name)) break;
	v++;
    }

    if ( *v && (*v)->v) return (*v);
    else return NULL;
}

#ifdef TEST_VERIFY

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#include "pbc_myconfig.h"

int debug = 1; /* in case one of the verifiers wants it */

int main(int argc, char *argv[])
{
    verifier *v = NULL;
    const char *errstr;
    int r;
    struct credentials *creds;

    if (argc < 3) {
        fprintf(stderr, "%s <verifier> <user> <pass> [realm] [service]\n", 
                argv[0]);
        exit(1);
    }

    libpbc_config_init(NULL, "vtest");

    v = get_verifier(argv[1]);
    if (!v) {
        printf("no such verifier: %s\n", argv[1]);
        exit(1);
    }

    /* first arg is pool */
    r = v->v(NULL, argv[2], argv[3], 
             argc > 4 ? argv[5] : NULL, 
             argc > 3 ? argv[4] : NULL,
             &creds, &errstr);
    if (r) {
        printf("verifier failed: %d %s\n", r, errstr);
        return r;
    }

    printf("success!\n");
    if (creds) {
        int s;
        struct credentials *newcreds;

        printf("got creds, size %d:\n", creds->sz);
        for (s = 0; s < creds->sz; s++) {
            if (isprint(creds->str[s])) putchar(creds->str[s]);
            else putchar('.');
        }
        putchar('\n');


        printf("\n"
               "attempting to get imap/cyrus.andrew.cmu.edu credential...\n");

        if (!v->cred_derive(NULL, creds, "vtest", "imap/cyrus.andrew.cmu.edu",
                            &newcreds) &&
            newcreds) {
            printf("got newcreds, size %d:\n", newcreds->sz);
            for (s = 0; s < newcreds->sz; s++) {
                if (isprint(newcreds->str[s])) putchar(newcreds->str[s]);
                else putchar('.');
            }
            putchar('\n');
        } else {
            printf("failed.\n");
        }
    }

    return 0;
}

#endif
