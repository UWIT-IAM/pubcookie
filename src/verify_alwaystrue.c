
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#include "verify.h"

extern int debug;

int alwaystrue_v(const char *userid,
		 const char *passwd,
		 const char *service,
		 const char *user_realm,
		 struct credentials **creds,
		 const char **errstr)
{

    if ( debug ) {
        fprintf( stderr, "alwaystrue_verifier: hello\n" );
        fprintf( stderr, "userid: %s\n", userid == NULL ? "(null)" : userid );
        fprintf( stderr, "passwd: %s\n", passwd == NULL ? "(null)" : passwd );
        fprintf( stderr, "service: %s\n", service == NULL ? "(null)" : service );
        fprintf( stderr, "user_realm: %s\n", 
                 user_realm == NULL ? "(null)" : user_realm );
    }

    if (errstr) *errstr = NULL;
    if (creds) *creds = NULL;

    return 0;
}

verifier alwaystrue_verifier = { "alwaystrue",
				&alwaystrue_v, NULL, NULL };
