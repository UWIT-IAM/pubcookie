/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file verify_alwaystrue.c
 * Alwaystrue verifier
 *
 * $Id: verify_alwaystrue.c,v 1.11 2003-07-02 23:27:05 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* Pretending we're Apache */
typedef void apr_pool_t;

#include "verify.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

extern int debug;

int alwaystrue_v(apr_pool_t * p, const char *userid,
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
