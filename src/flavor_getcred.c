/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file flavor_getcred.c
 * Getcred flavor
 *
 * $Id: flavor_getcred.c,v 1.17 2003-07-02 22:04:04 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#if defined (APACHE1_3)
# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"
#else
typedef void pool;
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_FNMATCH_H
# include <fnmatch.h>
#endif /* HAVE_FNMATCH_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif

#include "pbc_config.h"
#include "index.cgi.h"
#include "flavor.h"
#include "security.h"
#include "verify.h"
#include "pbc_logging.h"
#include "pbc_configure.h"
#include "libpubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/* we inherit from login_flavor_basic */
extern struct login_flavor login_flavor_basic;

static verifier *v = NULL;

/**
 * check to see if a server has authorization to request the 
 * credentials it is requested.
 * @param a silly pointer that we pass pretending we're Apache
 * @param server the name of the server
 * @param target the name of the target credentials
 * @returns 0 on success; negative numbers indicate
 * unauthorized. positive numbers are reserved for future "ask" features.
 */
static int check_authz(pool *p, const char *server, const char *target)
{
    int r = -1;
    FILE *f;
    const char *fname;
    int lineno;
    char buf[1024];

    fname = GETCRED_AUTHZ;

    f = pbc_fopen(p, fname, "r");
    if (!f) {
        pbc_log_activity(p, PBC_LOG_ERROR,
                         "can't open getcred authz file: %s, failing", 
                         fname);
        return -1;
    }

    lineno = 0;
    while (++lineno && fgets(buf, sizeof(buf), f)) {
        char *p, *q;
        int c;

        p = strchr(buf, '\n');
        if (!p) {
            pbc_log_activity(p, PBC_LOG_ERROR,
                             "ridiculous line in %s, line %d, skipping", 
                             fname, lineno);

            /* eat the rest of the line */
            c = getc(f);
            while (c != '\n' && c != EOF) {
                c = getc(f);
            }
            continue;
        }
        *p = '\0'; /* get rid of \n */

        /* 'buf' should now look like <server> <cred> {OK,NO,ASK} */
        p = buf;
        while (*p && !isspace(*p)) p++;
        if (!*p) {
            pbc_log_activity(p, PBC_LOG_ERROR,
                             "malformed line in %s, line %d, skipping", 
                             fname, lineno);
            continue;
        }
        *p++ = '\0';
        while (*p && isspace(*p)) p++;
        
        /* p points at <cred> */
        q = p;
        while (*q && !isspace(*q)) q++;
        if (!*q) {
            pbc_log_activity(p, PBC_LOG_ERROR,
                             "malformed line in %s, line %d, skipping", 
                             fname, lineno);
            continue;
        }
        *q++ = '\0';
        while (*q && isspace(*q)) q++;
        
        /* q points at OK/NO/ASK */
        /* xxx trailing whitespace in q */
        
        /* see if 'buf' matches server */
        if (fnmatch(buf, server, 0) != 0) {
            /* doesn't match */
            continue;
        }

        /* see if p matches target */
        if (fnmatch(p, target, 0) != 0) {
            continue;
        }

        /* check q */
        if (!strcasecmp(q, "OK")) {
            r = 0;
        } else if (!strcasecmp(q, "NO")) {
            r = -1;
        } else if (!strcasecmp(q, "ASK")) {
            r = 1;
        } else {
            pbc_log_activity(p, PBC_LOG_ERROR,
                             "unknown constraint '%s' in %s, line %d, skipping", 
                             q, fname, lineno);
            continue;
        }
    }

    if (r > 0) {
        pbc_log_activity(p, PBC_LOG_ERROR,
                         "flavor_getcred: constraint ASK unimplemented");
        r = -1;
    }

    pbc_fclose(p, f);

    return r;
}

static login_result process_getcred(pool *p, login_rec *l, login_rec *c,
				    const char **errstr)
{
    login_result basic_res;
    char *target;
    struct credentials *master, *newcreds;
    char *outbuf;
    int outlen;
    char *out64;

    assert(v != NULL);

    basic_res = login_flavor_basic.process_request(p, l, c, errstr);

    if (basic_res != LOGIN_OK) {
	/* we aren't authenticated; we need to do that */
	return basic_res;
    }

    /* what is the application asking for? */
    target = get_string_arg(p, PBC_GETVAR_CRED_TARGET, NO_NEWLINES_FUNC);
    if (!target) {
	/* hmm, the application didn't request any derived credentials */
        pbc_log_activity(p, PBC_LOG_ERROR, "flavor_getcred: %s not in greq", 
	       PBC_GETVAR_CRED_TARGET);
	*errstr = "no derived credentials were requested";
	return LOGIN_ERR;
    }

    /* check that l->host is authorized to have credentials for 'target'
       on behalf of l->user.
       
       we use 'l->host' as the name of the requesting server since
       it's the only thing that we can rely on since 'newcreds' will
       be encrypted so only l->host can read them.
    */
    if (check_authz(p, l->host, target)) { 
	pbc_log_activity(p, PBC_LOG_ERROR, 
                         "flavor_getcred: %s requested %s; request denied",
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
	    pbc_log_activity(p, PBC_LOG_ERROR, "flavor_getcred: malloc failed");
	    exit(1);
	}

	if (get_cookie(p, PBC_CRED_COOKIENAME, cookie, sizeof(cookie)-1) != PBC_OK) {
	    pbc_log_activity(p, PBC_LOG_ERROR, 
                             "flavor_getcred: couldn't retrieve cookie %s",
                             PBC_CRED_COOKIENAME);
	    *errstr = "no cached master credentials";
	    free(master);
	    return LOGIN_ERR;
	}

	/* decode base 64 */
	plain = (char *) malloc(strlen(cookie));
	if (!libpbc_base64_decode(p, (unsigned char *) cookie,
                               (unsigned char *) plain, &plainlen)) {
	    pbc_log_activity(p, PBC_LOG_ERROR, 
                             "flavor_getcred: malformed base64 %s",
                             PBC_CRED_COOKIENAME);
	    *errstr = "no cached master credentials (base64 error)";
	    free(master);
	    free(plain);
	    return LOGIN_ERR;
	}

	/* decrypt */
	if (libpbc_rd_priv(p, NULL, plain, plainlen, 
			   &(master->str), &(master->sz))) {
	    pbc_log_activity(p, PBC_LOG_ERROR,
                             "flavor_getcred: couldn't libpbc_rd_priv %s",
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
    if (v->cred_derive(p, master, l->host, target, &newcreds)) {
	pbc_log_activity(p, PBC_LOG_ERROR, "flavor_getcred: cred_derive failed");
	*errstr = "cred_derive failed";
	free(master->str);
	free(master);
	return LOGIN_ERR;
    }

    /* put the new credentials in a star cookie so they'll be sent to the 
       app server */
    /* encrypt */
    if (libpbc_mk_priv(p, l->host, newcreds->str, newcreds->sz,
		       &outbuf, &outlen)) {
	pbc_log_activity(p, PBC_LOG_ERROR,
                         "flavor_getcred: libpbc_mk_priv failed");
	*errstr = "libpbc_mk_priv failed";
	free(master->str);
	free(master);
	return LOGIN_ERR;
    }

    /* base64 */
    out64 = (char *) malloc(outlen * 4 / 3 + 20);
    libpbc_base64_encode(p, (unsigned char *) outbuf,
                          (unsigned char *) out64, outlen);

    /* set cookie */
    print_header(p, "Set-Cookie: %s=%s; domain=%s; path=/; secure\n",
		 PBC_CRED_TRANSFER_COOKIENAME,
		 out64,
		 enterprise_domain(p));

    /* cleanup */
    free(out64);
    free(outbuf);
    v->cred_free(p, newcreds);
    /* xxx this sucks; 'master' wasn't necessary allocated by the
       verifier, so it's not clear that we should be asking it to free
       it.  (and if we ever want to associate credentials with some
       outside resource, just allocating the credentials like we did
       above is insufficient. maybe we want a credentials_serialize
       and credentials_unserialize and make credentials completely opaque?
    */
    v->cred_free(p, master);

    /* tell the rest of the pubcookie code that we actually just finished
       verifying basic creds (but we don't touch l->creds_from_greq) */
    l->creds = login_flavor_basic.id;

    /* log success */
    pbc_log_activity(p, PBC_LOG_AUDIT, "passing credentials for %s %s to %s",
                     l->user, target, l->host);

    return LOGIN_OK;
}

/* make sure basic_verifier has a derive credential function */
static int init_getcred()
{
    const char *vname;
    int r;
    void *p;

    v = NULL;

    /* initialize basic */
    r = login_flavor_basic.init_flavor();
    if (r) return r;

    /* find the verifier configured */
    vname = libpbc_config_getstring(p, "basic_verifier", NULL);

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

