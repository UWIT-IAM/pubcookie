
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif /* HAVE_SYSLOG_H */

#include "pbc_config.h"
#include "index.cgi.h"
#include "flavor.h"
#include "security.h"
#include "verify.h"

/* we inherit from login_flavor_basic */
extern struct login_flavor login_flavor_basic;

static verifier *v = NULL;

static login_result process_getcred(login_rec *l, login_rec *c,
				    const char **errstr)
{
    login_result basic_res;
    char *target;
    struct credentials *master, *newcreds;
    char *outbuf;
    int outlen;
    char *out64;

    assert(v != NULL);

    basic_res = login_flavor_basic.process_request(l, c, errstr);

    if (basic_res != LOGIN_OK) {
	/* we aren't authenticated; we need to do that */
	return basic_res;
    }

    /* what is the application asking for? */
    target = get_string_arg(PBC_GETVAR_CRED_TARGET, NO_NEWLINES_FUNC);
    if (!target) {
	/* hmm, the application didn't request any derived credentials */
	syslog(LOG_ERR, "flavor_getcred: %s not in greq", 
	       PBC_GETVAR_CRED_TARGET);
	*errstr = "no derived credentials were requested";
	return LOGIN_ERR;
    }

    /* check that l->host is authorized to have credentials for 'target'
       on behalf of l->user.
       
       we use 'l->host' as the name of the target since it's the only thing
       that we can rely on. the newcreds will be encrypted so only
       l->host can read them.
    */
    /* xxx code */
    if (0) { /* xxx test */
	syslog(LOG_ERR, "flavor_getcred: %s requested %s; request denied",
	       l->host, target);
	*errstr = "application not allowed to request these credentials";
	return LOGIN_ERR;
    }

    /* retrieve the cached credentials */
    if (l->flavor_extension) {
	/* we cheat here; really we should have a method of storing
	 these credentials in a safe fashion that guarantees they
	 get deallocated later */
	master = (struct credentials *) l->flavor_extension;
	l->flavor_extension = NULL;
    } else {
	/* these better be available in cookie form */
	char cookie[4096];
	char *plain;
	int plainlen;

	master = (struct credentials *) malloc(sizeof(struct credentials));
	if (!master) {
	    syslog(LOG_ERR, "flavor_getcred: malloc failed");
	    exit(1);
	}

	if (get_cookie(PBC_CRED_COOKIENAME, cookie, sizeof(cookie)-1) != PBC_OK) {
	    syslog(LOG_ERR, "flavor_getcred: couldn't retrieve cookie %s",
		   PBC_CRED_COOKIENAME);
	    *errstr = "no cached master credentials";
	    free(master);
	    return LOGIN_ERR;
	}

	/* decode base 64 */
	plain = (char *) malloc(strlen(cookie));
	if (!libpbc_base64_decode(cookie, plain, &plainlen)) {
	    syslog(LOG_ERR, "flavor_getcred: malformed base64 %s",
		   PBC_CRED_COOKIENAME);
	    *errstr = "no cached master credentials (base64 error)";
	    free(master);
	    free(plain);
	    return LOGIN_ERR;
	}

	/* decrypt */
	if (libpbc_rd_priv(NULL, plain, plainlen, 
			   &(master->str), &(master->sz))) {
	    syslog(LOG_ERR, "flavor_getcred: couldn't libpbc_rd_priv %s",
		   PBC_CRED_COOKIENAME);
	    *errstr = "no cached master credentials (libpbc_rd_priv)";
	    free(master);
	    free(plain);
	    return LOGIN_ERR;
	}
	free(plain);
    }

    /* derive those credentials and throw them in a cookie */
    /* we pass 'l->host' in to cred_derive because that's what we're going
       to use as the peer when we encrypt newcreds */
    if (v->cred_derive(master, l->host, target, &newcreds)) {
	syslog(LOG_ERR, "flavor_getcred: cred_derive failed");
	*errstr = "cred_derive failed";
	free(master->str);
	free(master);
	return LOGIN_ERR;
    }

    /* put the new credentials in a star cookie so they'll be sent to the 
       app server */
    /* encrypt */
    if (libpbc_mk_priv(l->host, newcreds->str, newcreds->sz,
		       &outbuf, &outlen)) {
	syslog(LOG_ERR, "flavor_getcred: libpbc_mk_priv failed");
	*errstr = "libpbc_mk_priv failed";
	free(master->str);
	free(master);
	return LOGIN_ERR;
    }

    /* base64 */
    out64 = (char *) malloc(outlen * 4 / 3 + 20);
    libpbc_base64_encode(outbuf, out64, outlen);

    /* set cookie */
    print_header("Set-Cookie: %s=%s; domain=%s; path=/; secure\n",
		 PBC_CRED_TRANSFER_COOKIENAME,
		 out64,
		 enterprise_domain());

    /* cleanup */
    free(out64);
    free(outbuf);
    v->cred_free(newcreds);
    /* xxx this sucks; 'master' wasn't necessary allocated by the
       verifier, so it's not clear that we should be asking it to free
       it.  (and if we ever want to associate credentials with some
       outside resource, just allocating the credentials like we did
       above is insufficient. maybe we want a credentials_serialize
       and credentials_unserialize and make credentials completely opaque?
    */
    v->cred_free(master);

    /* tell the rest of the pubcookie code that we actually just finished
       verifying basic creds (but we don't touch l->creds_from_greq) */
    l->creds = login_flavor_basic.id;

    /* log success */
    syslog(LOG_INFO, "passing credentials for %s %s to %s",
	   l->user, target, l->host);

    return LOGIN_OK;
}

/* make sure basic_verifier has a derive credential function */
static int init_getcred(void)
{
    const char *vname;
    int r;

    v = NULL;

    /* initialize basic */
    r = login_flavor_basic.init_flavor();
    if (r) return r;

    /* find the verifier configured */
    vname = libpbc_config_getstring("basic_verifier", NULL);

    if (!vname) {
	fprintf(stderr, "flavor_basic: no verifier configured\n");
	return -1;
    }

    v = get_verifier(vname);

    if (!v || !v->cred_derive) {
	fprintf(stderr, "flavor_getcred: verifier %s not suitable\n", vname);
	v = NULL;
	return -1;
    }

    return 0;
}

struct login_flavor login_flavor_getcred =
{
    "getcred", /* name */
    PBC_GETCRED_CRED_ID, /* id; see libpbc_get_credential_id() */
    &init_getcred, /* init_flavor() */
    &process_getcred /* process_request() */
};

