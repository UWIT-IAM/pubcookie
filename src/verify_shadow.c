/**
 *  the shadow_verifier verifies a username and password 
 *  against /etc/shadow.  sadly, it must be able to read
 *  /etc/shadow.  
 *
 *  @return 0 on success, -1 if user/pass doesn't match, -2 on system error
 */

#include <stdlib.h>
#include "verify.h"

#ifdef HAVE_SHADOW
#include <shadow.h>
#include <crypt.h>
#include <string.h>

static int shadow_v(const char *userid,
		    const char *passwd,
		    const char *service,
		    const char *user_realm,
		    struct credentials **creds,
		    const char **errstr)
{

    struct spwd * shadow;
    char * crypted;

    if (errstr) *errstr = NULL;
    if (creds) *creds = NULL;

    if (!userid) {
       *errstr = "no userid to verify";
       return -1;
    }

    if (!passwd) {
       *errstr = "no password to verify";
       return -1;
    }

    setspent();
    shadow = getspnam(userid);
    endspent();

    if (shadow == NULL) {
       *errstr = "unable to get entry from /etc/shadow";
       return -2;
    }

    crypted = crypt(passwd, shadow->sp_pwdp);

    if (crypted == NULL) {
       *errstr = "error crypt'ing passwd";
       return -2;
    }

    if (strcmp(shadow->sp_pwdp, crypted) == 0) {
       return 0;
    }
    
    *errstr=("username/password pair is incorrect");
    return -1;
}

#else /* HAVE_SHADOW */

static int shadow_v(const char *userid,
		    const char *passwd,
		    const char *service,
		    const char *user_realm,
		    struct credentials **creds,
		    const char **errstr)
{
    if (creds) *creds = NULL;

    *errstr = "shadow verifier not implemented";
    return -1;
}

#endif /* HAVE_SHADOW */

verifier shadow_verifier = { "shadow", &shadow_v, NULL, NULL };
