#include <stdlib.h>

#include "verify.h"

int alwaystrue_v(const char *userid,
		 const char *passwd,
		 const char *service,
		 const char *user_realm,
		 struct credentials **creds,
		 const char **errstr)
{
    if (errstr) *errstr = NULL;
    if (creds) *creds = NULL;

    return 0;
}

verifier alwaystrue_verifier = { "alwaystrue",
				&alwaystrue_v, NULL, NULL };
