/*

    Modified further at Carnegie Mellon University
    Modified Kerberos code, modified at University of Washington
    Copyright 1995,1996,1997,1998 by the Massachusetts Institute of Technology.
       All Rights Reserved.

 */

/*
 * $Revision: 1.8 $
 */

/* login cgi includes */
#include "index.cgi.h"
#include "verify.h"
#include "pbc_myconfig.h"

#ifdef HAVE_KRB5

/* LibC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>

/* krb5  */
#include <com_err.h>
#include <krb5.h>

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*15 /* xxx 15 minutes */

static char thishost[BUFSIZ];

static int save_tf(const char *tfname, struct credentials **credsp)
{
    FILE *f;
    struct stat sbuf;

    assert(tfname != NULL && credsp != NULL);

    *credsp = malloc(sizeof(struct credentials));
    if (!*credsp) {
	syslog(LOG_ERR, "verify_kerberos5: malloc failed");
	return -1;
    }
    (*credsp)->str = NULL;

    f = fopen(tfname, "r");
    if (!f) {
	syslog(LOG_ERR, "verify_kerberos5: can't open %s: %m", tfname);
	return -1;
    }

    if (fstat(fileno(f), &sbuf) < 0) {
	syslog(LOG_ERR, "verify_kerberos5: fstat %s: %m", tfname);
	return -1;
    }

    (*credsp)->sz = sbuf.st_size;
    (*credsp)->str = malloc(sbuf.st_size * sizeof(char));
    if (!(*credsp)->str) {
	syslog(LOG_ERR, "verify_kerberos5: malloc failed");
	goto cleanup;
    }

    if (fread((*credsp)->str, sbuf.st_size, 1, f) != 1) {
	syslog(LOG_ERR, "verify_kerberos5: short read %s: %m", tfname);
	goto cleanup;
    }

    fclose(f);
    return 0;

 cleanup:
    fclose(f);
    if ((*credsp)->str) free((*credsp)->str);
    free(*credsp);

    return -1;
}

static int unsave_tf(const char *tfname, struct credentials *creds)
{
    FILE *f;

    assert(tfname != NULL && creds != NULL);

    f = fopen(tfname, "w");
    if (!f) {
	syslog(LOG_ERR, "verify_kerberos5: can't open %s: %m", tfname);
	return -1;
    }

    if (fwrite(creds->str, creds->sz, 1, f) != 1) {
	syslog(LOG_ERR, "verify_kerberos5: can't write %s: %m", tfname);
	fclose(f);
	unlink(tfname);
	return -1;
    }

    if (fclose(f) != 0) {
	syslog(LOG_ERR, "verify_kerberos5: can't close %s: %m", tfname);
	unlink(tfname);
	return -1;
    }

    return 0;
}

static void creds_free(struct credentials *creds)
{
    if (creds->str) free(creds->str);
    if (creds) free(creds);
}

static int creds_derive(struct credentials *creds,
			const char *app,
			const char *target,
			struct credentials **outcredsp)
{
    char tfname[40];
    char tfname_target[40];
    char *realm = NULL;
    char *s, *t;
    krb5_context context;
    krb5_ccache ccache;
    krb5_ccache ccache_target;
    krb5_auth_context auth_context;
    krb5_creds request, *newcreds;
    krb5_data packet;
    int r = -1;

    assert(creds != NULL);
    assert(app != NULL && target != NULL);

    memset(&request, 0, sizeof(request));

    snprintf(tfname, sizeof(tfname), "/tmp/k5cc_%d", getpid());
    snprintf(tfname_target, sizeof(tfname_target), "/tmp/k5cc_%d_", getpid());

    s = strdup(target);
    if (!s) {
	return -1;
    }

    /* unpack 'creds' into a ticket file */
    if (unsave_tf(tfname, creds) < 0) {
	return -1;
    }

    /* examine the ticket file */
    if (krb5_init_context(&context)) {
	return -1;
    }

    if (krb5_cc_resolve(context, tfname, &ccache)) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: krb5_cc_resolve failed",
	       target);
	krb5_free_context(context);
	return -1;
    }

    realm = strchr(s, '@');
    if (realm) {
	*realm++ = '\0';
	realm = strdup(realm); /* so we can free it later */
    } else {
	if (krb5_get_default_realm(context, &realm)) {
	    realm = NULL;
	}
    }

    if (!realm) {
	syslog(LOG_ERR,
	       "verify_kerberos5: creds_derive %s: couldn't determine realm", 
	       target);
	goto cleanup;
    }

    /* get the hostname out */
    t = strchr(s, '/');
    if (t) *t++ = '\0';

    /* who am i? */
    if (krb5_cc_get_principal(context, ccache, &(request.client))) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: who am i?", 
	       target);
	goto cleanup;
    }

    /* build requested principal */
    if (krb5_build_principal(context, &request.server, 
			     strlen(realm), realm, s, t, NULL)) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: couldn't build principal", 
	       target);
	goto cleanup;
    }

    /* fetch the request ticket */
    if (krb5_get_credentials(context, 0, ccache, &request, &newcreds)) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: krb5_get_credentials failed",
	       target);
	goto cleanup;
    }

    /* save the new credentials in a new ccache */
    if (krb5_cc_resolve(context, tfname_target, &ccache_target)) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: krb5_cc_resolve failed",
	       target);
	goto cleanup;
    }

    if (krb5_cc_initialize (context, ccache_target, request.client)) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: krb5_cc_initialize failed",
	       target);
	goto cleanup;
    }

    if (krb5_cc_store_cred(context, ccache_target, newcreds)) {
	syslog(LOG_ERR, 
	       "verify_kerberos5: creds_derive %s: krb5_cc_store_cred failed",
	       target);
	goto cleanup;
    }

    /* bundle up the new ticket */
    if (save_tf(tfname_target, outcredsp) < 0) {
	syslog(LOG_ERR, "verify_kerberos5: save_tf failed");
	goto cleanup;
    }

    /* whew! done */
    r = 0;

 cleanup:
    if (s) free(s);
    if (request.client) krb5_free_principal(context, request.client);
    if (request.server) krb5_free_principal(context, request.server);
    krb5_cc_destroy(context, ccache);
    krb5_cc_destroy(context, ccache_target);
    unlink(tfname);
    unlink(tfname_target);
    krb5_free_context(context);

    return r;
}

/*
 * returns 0 success; non-0 on failure
 */
static int k5support_verify_tgt(krb5_context context, 
				krb5_ccache ccache,
				krb5_auth_context *auth_context,
				const char **errstr)
 
{
    krb5_principal server;
    krb5_data packet;
    krb5_keyblock *keyblock = NULL;
    krb5_error_code k5_retcode;
    int result = -1;

    krb5_keytab keytab;
    krb5_pointer keytabname;


    if (errstr) {
	*errstr = NULL;
    }

    if (krb5_sname_to_principal(context, NULL, NULL,
				KRB5_NT_SRV_HST, &server)) {
	*errstr = "krb5_sname_to_principal() failed";
	return -1;
    }

    keytabname = (krb5_pointer) libpbc_config_getstring("kerberos5_keytab",
                                                        NULL);

    if (krb5_kt_resolve(context, keytabname, &keytab)) {
       *errstr = "unable to resolve keytab";
       goto fini;
    }

    if (krb5_kt_read_service_key(context, keytabname, server, 0,
				 0, &keyblock)) {
        *errstr = "unable to read service key";
	goto fini;
    }

    if (keyblock) {
	free(keyblock);
    }

    krb5_data_zero(&packet);

    k5_retcode = krb5_mk_req(context, auth_context, 0, "host", 
			     thishost, NULL, ccache, &packet);
    if (*auth_context) {
	krb5_auth_con_free(context, *auth_context);
	*auth_context = NULL;
    }

    if (k5_retcode) {
        *errstr = "krb5_mk_req failed";
	goto fini;
    }

    if (k5_retcode = krb5_rd_req(context, auth_context, &packet, 
		                 server, keytab, NULL, NULL)) {
        *errstr = "krb5_rd_req failed";
	goto fini;
    }
  
    /* all is good now */
    result = 0;
 fini:
    krb5_free_principal(context, server);

    return result;
}

/* returns 0 on success; non-zero on failure */
static int kerberos5_v(const char *userid,
		       const char *passwd,
		       const char *service,
		       const char *user_realm,
		       struct credentials **credsp,
		       const char **errstr)
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal auth_user;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;
    int result = -1;
    char tfname[40];
    char *realm = NULL;

    if (credsp) *credsp = NULL;

    if (errstr) { 
	*errstr = NULL; 
    }

    if (!thishost[0] && gethostname(thishost, BUFSIZ) < 0) {
        *errstr = "gethostname failed";
	return -1;
    }
    thishost[BUFSIZ-1] = '\0';

    if (!userid) {
       *errstr = "no userid to verify";
       return -1;
    }
    if (!passwd) {
       *errstr = "no password to verify";
       return -1;
    }
  
    if (krb5_init_context(&context)) {
	return -1;
    }

    /* add the other login servers to the acceptable IP addresses */

    if (!user_realm) {
       if (!krb5_get_default_realm(context, &realm)) {
	   /* don't forget to free this if you care */
	   user_realm = realm;
       } else { 
	   *errstr = "can't determine realm";
	   krb5_free_context(context);
	   return -1;
       }
    }

    if (krb5_build_principal (context, &auth_user, strlen(user_realm),
                              user_realm, userid, NULL)) {
	krb5_free_context(context);
	free(realm);
	return -1;
    }

    /* create a new CCACHE so we don't stomp on anything */
    snprintf(tfname,sizeof(tfname), "/tmp/k5cc_%d", getpid());
    if (krb5_cc_resolve(context, tfname, &ccache)) {
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	free(realm);
	return -1;
    }

    if (krb5_cc_initialize (context, ccache, auth_user)) {
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	free(realm);
	return -1;
    }

    krb5_get_init_creds_opt_init(&opts);
    krb5_get_init_creds_opt_set_tkt_life(&opts, KRB5_DEFAULT_LIFE);
    if (krb5_get_init_creds_password(context, &creds, 
				     auth_user, passwd, NULL, NULL, 
				     0, NULL, &opts)) {
	krb5_cc_destroy(context, ccache);
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	free(realm);
        *errstr = "can't get tgt";
	return -1;
    }

    /* at this point we should have a TGT. Let's make sure it is valid */
    if (krb5_cc_store_cred(context, ccache, &creds)) {
	krb5_free_principal(context, auth_user);
	krb5_cc_destroy(context, ccache);
	krb5_free_context(context);
	free(realm);
        *errstr = "can't verify tgt";
	return -1;
    }

    /* save the TGT if we were asked to */
    if (credsp && save_tf(tfname, credsp) < 0) {
	syslog(LOG_ERR, "verify_kerberos5: save_tf failed");
    }

    result = k5support_verify_tgt(context, ccache, &auth_context, errstr);

#if 0
    /* xxx this seems like the way it "should" be done instead of the
       save_tf() way */
    /* save the TGT */

    if (!result && credsp) {
	int r = 0;
	krb5_kdc_flags flags;
	krb5_principal server = 0;
	krb5_principal client = 0;
	krb5_data forw_creds;
	struct sockaddr_in sin;
	int sa_size;
	krb5_address addr;

	memset(&flags, 0, sizeof(flags));
	memset(&forw_creds, 0, sizeof(forw_creds));

	if (!auth_context) {
	    /* initialize the auth_context */
	    r = krb5_auth_con_init(context, &auth_context);
	}

	/* we're forwarding these credentials to ourselves; we'll 
	   mark them as good for anyone*/
	if (!r) {
	    r = krb5_anyaddr(context, AF_INET, (struct sockaddr *) &sin, 
			     &sa_size, 0);
	}

	if (!r) {
	    r = krb5_sockaddr2address(context, (struct sockaddr *) &sin, 
				      &addr);
	}

	if (!r) {
	    r = krb5_auth_con_setaddrs(context, auth_context,
				       &addr, &addr);
	}

	/* get the opaque data to save for later */
	if (!r) {
	    r = krb5_get_forwarded_creds(context, auth_context, ccache,
					 flags.i, thishost, &creds,
					 &forw_creds);
	}

	/* put it into a struct credentials */
	if (!r) {
	    *credsp = malloc(sizeof(struct credentials));
	    if (*credsp) {
		(*credsp)->sz = forw_creds.length;
		(*credsp)->str = forw_creds.data;
	    } else {
		syslog(LOG_ERR, "verify_kerberos5: malloc() failed");
	    }
	} else {
	    /* krb error */
	    syslog(LOG_ERR, "verify_kerberos5: error getting forwarded creds: %s",
		   error_message(r));
	}
    }
#endif

    /* destroy any tickets we had */
    if (auth_context) {
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL;
    }
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, auth_user);
    krb5_cc_destroy(context, ccache);
    krb5_free_context(context);
    free(realm);

    if (result != 0 && credsp && *credsp) {
	/* destroy the credentials we saved */
	creds_free(*credsp);
    }

    return result;
}

#else /* HAVE_KRB5 */

static void creds_free(struct credentials *creds)
{
    /* No-op 'cuz we aren't doing krb5! */
}
static int creds_derive(struct credentials *creds,
			const char *app,
			const char *target,
			struct credentials **outcredsp)
{
    /* No-op 'cuz we aren't doing krb5! */
    /* Return success 'cuz nothing happened. */
     
    return 0;
}

static int kerberos5_v(const char *userid,
		       const char *passwd,
		       const char *service,
		       const char *user_realm,
		       struct credentials **creds,
		       const char **errstr)
{
    if (creds) *creds = NULL;

    *errstr = "kerberos5 not implemented";
    return -1;
}



#endif /* HAVE_KRB5 */

verifier kerberos5_verifier = { "kerberos_v5", 
				&kerberos5_v, &creds_free, &creds_derive };
