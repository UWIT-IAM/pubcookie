/*

    Copyright 2001, University of Washington.  All rights reserved.
    Copyright 1995,1996,1997,1998 by the Massachusetts Institute of Technology.
       All Rights Reserved.


     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: https:/www.washington.edu/pubcookie/
    Written by the Pubcookie Team

    this is the kerberos auth portion of the pubcookie login cgi.

 */

/*
    $Id: index.cgi_krb.c,v 1.2 2001-05-09 20:31:27 willey Exp $
 */


/* LibC */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* krb5  */
#include <com_err.h>
#include <krb5.h>
/* login cgi includes */
#include "index.cgi.h"

char *auth_kdc(const char *username, const char *passwd)
{

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*60*10 /* 10 hours */

    extern int optind;
    extern char *optarg;
    
    krb5_data tgtname = {
        0,
        KRB5_TGS_NAME_SIZE,
        KRB5_TGS_NAME
    };

    /*
     * Try no preauthentication first; then try the encrypted timestamp
     */

    krb5_preauthtype * preauth = NULL;
    krb5_context kcontext;
    krb5_deltat lifetime = KRB5_DEFAULT_LIFE;       /* -l option */
    int options = KRB5_DEFAULT_OPTIONS;
    krb5_error_code code;
    krb5_principal me;
    krb5_principal kserver;
    krb5_creds my_creds;
    krb5_timestamp now;
    krb5_address **addrs = (krb5_address **)0;
    char *client_name;

    char	*ret = NULL;

    code = krb5_init_context(&kcontext);
    if(code) {
        log_error(2, "auth-kdc", 1, "auth_kdc: %s while initializing krb5\n", 
			error_message(code));
	abend("can't init krb5 context");
    }

    if((code = krb5_timeofday(kcontext, &now))) {
	log_error(2, "auth-kdc", 1, "auth_kdc: %s while getting time of day\n", 
			error_message(code));
	abend("can't get the time of day");
    }

    /* just use the name we give you and default domain */
    if ((code = krb5_parse_name (kcontext, username, &me))) {
	 log_error(2, "auth-kdc", 1, "auth_kdc: ABEND %s when parsing name %s\n", 
			error_message(code), username);
	 abend("krb5 can't parse username");
    }
    
    if ((code = krb5_unparse_name(kcontext, me, &client_name))) {
	log_error(2, "auth-kdc", 1, "auth_kdc: %s when unparsing name\n", 
			error_message(code));
	abend("misc. krb5 problem");
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    /* me is the pricipal */
    my_creds.client = me;

    /* get kserver name */
    if((code = krb5_build_principal_ext(kcontext, &kserver,
                        krb5_princ_realm(kcontext, me)->length,
                        krb5_princ_realm(kcontext, me)->data,
                        tgtname.length, tgtname.data,
                        krb5_princ_realm(kcontext, me)->length,
                        krb5_princ_realm(kcontext, me)->data,
                        0))) {
	log_error(2, "auth-kdc", 1, "auth_kdc: %s while building kserver name\n", 
			error_message(code));
	return("failed");
    }
	
    my_creds.server = kserver;

    my_creds.times.starttime = 0;	/* start timer when request
					   gets to KDC */
    my_creds.times.endtime = now + lifetime;

    my_creds.times.renew_till = 0;

    code = krb5_get_in_tkt_with_password(kcontext, options, addrs,
					      NULL, preauth, passwd, 0,
					      &my_creds, 0);

    if (code) {
	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
#ifdef DEBUG
	    log_message("auth_kdc: Password incorrect username: %s\n", 
			username);
#else
            ;
#endif
	else 
#ifdef DEBUG
	    log_message("auth_kdc: %s while checking credntials username: %s\n",
			error_message(code), username);
#else
            ;
#endif
	ret = strdup("Auth failed");
    }

    /* my_creds is pointing at server */
    krb5_free_principal(kcontext, kserver);

    krb5_free_context(kcontext);
    
    clear_error("auth-kdc", "auth_kdc ok");

    return(ret);

}

