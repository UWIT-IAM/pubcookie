#include "flavor.h"

extern struct login_flavor login_flavor_basic;
struct login_flavor login_flavor_getcred;

static struct login_flavor *flavors[] = {
    &login_flavor_basic,
    &login_flavor_getcred,
    NULL
};

struct login_flavor *get_flavor(const char id)
{
    struct login_flavor **f = flavors;

    while (*f) {
	if ((*f)->id == id) break;
	f++;
    }

    return (*f);
}
