
#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#include "flavor.h"

#ifdef HAVE_DMALLOC_H
# ifndef APACHE
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

extern struct login_flavor login_flavor_basic;
/* extern struct login_flavor login_flavor_uwash; */
extern struct login_flavor login_flavor_getcred;

static struct login_flavor *flavors[] = {
    &login_flavor_basic,
    &login_flavor_getcred,
/*    &login_flavor_uwash, */
    NULL
};

struct login_flavor *get_flavor(pool *p, const char id)
{
    struct login_flavor **f = flavors;

    while (*f) {
	if ((*f)->id == id) break;
	f++;
    }

    return (*f);
}
