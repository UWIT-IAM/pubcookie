/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file flavor.c
 * Flavor generic code
 *
 * $Id: flavor.c,v 1.13 2004-02-10 00:42:14 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#include "flavor.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

extern struct login_flavor login_flavor_basic;
extern struct login_flavor login_flavor_getcred;
#ifdef ENABLE_UWSECURID
extern struct login_flavor login_flavor_uwsecurid;
#endif

/**
 */
static struct login_flavor *flavors[] = {
    &login_flavor_basic,
    &login_flavor_getcred,
#ifdef ENABLE_UWSECURID
    &login_flavor_uwsecurid,
#endif
    NULL
}; /*! list of available flavors */

struct login_flavor *get_flavor(pool *p, const char id)
{
    struct login_flavor **f = flavors;

    while (*f) {
	if ((*f)->id == id) break;
	f++;
    }

    return (*f);
}
