#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "verify.h"

/* verifiers we might have access to */
extern verifier kerberos4_verifier;
extern verifier kerberos5_verifier;
extern verifier ldap_verifier;
extern verifier alwaystrue_verifier;

/* verifiers that we actually compiled */
static verifier *verifiers[] = {
    &kerberos4_verifier,
    &kerberos5_verifier,
    &ldap_verifier,
    &alwaystrue_verifier,
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

#include <ctype.h>

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

    v = get_verifier(argv[1]);
    if (!v) {
        printf("no such verifier: %s\n", argv[1]);
        exit(1);
    }

    if (r = v->v(argv[2], argv[3], 
                 argc > 4 ? argv[5] : NULL, 
                 argc > 3 ? argv[4] : NULL,
                 &creds, &errstr)) {
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

        if (!v->cred_derive(creds, "vtest", "imap/cyrus.andrew.cmu.edu",
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
