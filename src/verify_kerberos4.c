/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file verify_kerberos4.c
 * Kerberos 4 verifier
 *
 * $Id: verify_kerberos4.c,v 1.12 2003-07-03 04:25:21 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

/* Pretending we're Apache */
typedef void pool;

#include "verify.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

static int kerberos4_v(pool * p, const char *userid,
		       const char *passwd,
		       const char *service,
		       const char *user_realm,
		       struct credentials **creds,
		       const char **errstr)
{
    if (creds) *creds = NULL;

    *errstr = "kerberos4 not implemented";
    return -1;
}

verifier kerberos4_verifier = { "kerberos_v4",
				&kerberos4_v, NULL, NULL };
