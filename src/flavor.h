/* a flavor specifies:
 * - the policy of when freerides are allowed
 * - what the layout of the login page is, how login messages are printed. 
 */

#ifndef INCLUDED_FLAVOR_H
#define INCLUDED_FLAVOR_H

#include "index.cgi.h"

typedef enum {
    LOGIN_OK = 0,		/* proceed with request */
    LOGIN_ERR = 1,		/* request not allowed */
    LOGIN_INPROGRESS = 2	/* return to login page */
} login_result;

struct login_flavor {
    const char id;

    /* initialize this flavor; if non-zero return, this flavor is not
       available */
    int (*init_flavor)(void);

    /* given a login request 'l' and a (possibly NULL) login cookie 'c',
       process the request.  if there are insufficient credentials,
       print out a login form and return accordingly. */
    login_result (*process_request)(login_rec *l, login_rec *c, 
				    const char **errstr);
};

#endif /* INCLUDED_FLAVOR_H */
