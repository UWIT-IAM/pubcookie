#include <stdlib.h>
#include <string.h>

#include "verify.h"

/* verifiers we might have access to */
extern plaintext_verifier kerberos4_verifier;
extern plaintext_verifier kerberos5_verifier;
extern plaintext_verifier ldap_verifier;
extern plaintext_verifier alwaystrue_verifier;

struct verify_s {
    const char *name;
    plaintext_verifier *verify;
};

/* verifiers that we actually compiled */
static struct verify_s verifiers[] = {
    { "kerberos_v4", &kerberos4_verifier },
    { "kerberos_v5", &kerberos5_verifier },
    { "ldap", &ldap_verifier },
    { "alwaystrue", &alwaystrue_verifier },
    { NULL, NULL }
};

/* given a string, find the corresponding verifier */
plaintext_verifier *get_verifier(const char *name)
{
    struct verify_s *v = verifiers;
    while (v->name) {
	if (!strcasecmp(v->name, name)) break;
	v++;
    }

    return v->verify;
}
