#include <stdlib.h>

#include "verify.h"

int alwaystrue_verifier(const char *userid,
			const char *passwd,
			const char *service,
			const char *user_realm,
			const char **errstr)
{
    if (errstr) *errstr = NULL;

    return 0;
}
