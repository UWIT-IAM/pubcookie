/*

    Modified further at Carnegie Mellon University
    Modified Kerberos code, modified at University of Washington
    Copyright 1995,1996,1997,1998 by the Massachusetts Institute of Technology.
       All Rights Reserved.

 */

/*
    $Id: verify_kerberos5.c,v 1.2 2002-05-23 19:32:59 jteaton Exp $
 */

#ifdef HAVE_KRB5

/* LibC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

/* krb5  */
#include <com_err.h>
#include <krb5.h>

/* login cgi includes */
#include "index.cgi.h"
#include "verify.h"

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*15 /* 15 minutes */

/*
 * returns 0 success; non-0 on failure
 */
static int k5support_verify_tgt(krb5_context context, 
				krb5_ccache ccache,
				const char **errstr)
 
{
    krb5_principal server;
    krb5_data packet;
    krb5_keyblock *keyblock = NULL;
    krb5_auth_context auth_context = NULL;
    krb5_error_code k5_retcode;
    char thishost[BUFSIZ];
    int result = -1;

    if (errstr) {
	*errstr = NULL;
    }
    if (krb5_sname_to_principal(context, NULL, NULL,
				KRB5_NT_SRV_HST, &server)) {
	*errstr = "krb5_sname_to_principal() failed";
	return -1;
    }

    if (krb5_kt_read_service_key(context, NULL, server, 0,
				 0, &keyblock)) {
        *errstr = "unable to read service key";

	goto fini;
    }

    if (keyblock) {
	free(keyblock);
    }

    /* this duplicates work done in krb5_sname_to_principal
     * oh well.
     */
    if (gethostname(thishost, BUFSIZ) < 0) {
        *errstr = "gethostname failed";

	goto fini;
    }
    thishost[BUFSIZ-1] = '\0';

    krb5_data_zero(&packet);
    k5_retcode = krb5_mk_req(context, &auth_context, 0, "host", 
			     thishost, NULL, ccache, &packet);

    if (auth_context) {
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL;
    }

    if (k5_retcode) {
        *errstr = "krb5_mk_req failed";
	goto fini;
    }

    if (krb5_rd_req(context, &auth_context, &packet, 
		    server, NULL, NULL, NULL)) {
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
int kerberos5_verifier(const char *userid,
		       const char *passwd,
		       const char *service,
		       const char *user_realm,
		       const char **errstr)
{
    krb5_context context;
    krb5_ccache ccache = NULL;
    krb5_principal auth_user;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;
    int result = -1;
    char tfname[40];

    if (errstr) { 
	*errstr = NULL; 
    }

    if (!userid) {
       *errstr = "no userid to verify";
       return -1;
    }
    if (!passwd) {
       *errstr = "no password to verify";
       return -1;
    }

    /* xxx verify that user_realm is the local realm
       (or we have to do evil crossrealm foo) !!! */
  
    if (krb5_init_context(&context)) {
	return -1;
    }
    
    if (krb5_parse_name (context, userid, &auth_user)) {
	krb5_free_context(context);
	return -1;
    }

    /* create a new CCACHE so we don't stomp on anything */
    snprintf(tfname,sizeof(tfname), "/tmp/k5cc_%d", getpid());
    if (krb5_cc_resolve(context, tfname, &ccache)) {
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	return -1;
    }

    if (krb5_cc_initialize (context, ccache, auth_user)) {
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
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
	return -1;
    }

    /* at this point we should have a TGT. Let's make sure it is valid */
    if (krb5_cc_store_cred(context, ccache, &creds)) {
	krb5_free_principal(context, auth_user);
	krb5_cc_destroy(context, ccache);
	krb5_free_context(context);
	return -1;
    }

    result = k5support_verify_tgt(context, ccache, errstr);

    /* destroy any tickets we had */
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, auth_user);
    krb5_cc_destroy(context, ccache);
    krb5_free_context(context);
    return result;
}

#else /* HAVE_KRB5 */

int kerberos5_verifier(const char *userid,
			const char *passwd,
			const char *service,
			const char *user_realm,
			const char **errstr)
{
    *errstr = "kerberos5 not implemented";
    return -1;
}


#endif /* HAVE_KRB5 */

