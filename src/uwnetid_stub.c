
/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: https:/www.washington.edu/pubcookie/
    Written by the Pubcookie Team

    this is a stub for testing the kdc stuff in the login cgi

 */

/*
    $Id: uwnetid_stub.c,v 1.1 2000-03-03 01:50:42 willey Exp $
 */


/* LibC */
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* openssl */
#include <pem.h>
/* krb5  */
#include <com_err.h>
#include <krb5.h>
/* securid */
#include "securid_securid.h"
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
/* cgic */
#include <cgic.h>


  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
 /*	general utility thingies                                            */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 


/* write a log message via whatever mechanism                                 */
void log_message(const char *format, ...) 
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format), "%s: %s\n", 
			ANY_LOGINSRV_MESSAGE, format);
    vsnprintf(message, sizeof(message), new_format, args);
    va_end(args);
    libpbc_debug(message);

}

/* send a message to pilot                                                    */
void send_pilot_message(char *message) 
{

    /* pilot is no longer supported by ndc-sysmgt, so whatever */

}

/* logs the message and forwards it on to pilot                               */
void log_error(const char *format,...)
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format), "%s: %s", SYSERR_LOGINSRV_MESSAGE, format);
    vsnprintf(message, sizeof(message), new_format, args);
    log_message(message);
    send_pilot_message(message);
    va_end(args);

}

/* when things go wrong and you're not sure what else to do                   */
/* a polite bailing out                                                       */
void abend(char *message) 
{

    log_error(message);
    exit(0);

}


char *check_login_uwnetid(char *user, char *pass)
{

#ifdef DEBUG
    fprintf(stderr, "check_login_uwnetid: hello\n");
#endif 

    if( auth_kdc(user, pass) == OK )
        return(CHECK_LOGIN_RET_SUCCESS);
    else
        return(CHECK_LOGIN_RET_FAIL);

}


int auth_kdc(char *username, char *passwd)
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

    int		ret = 1;

    code = krb5_init_context(&kcontext);
    if(code) {
        log_error("auth_kdc: %s while initializing krb5\n", 
			error_message(code));
	abend("can't init krb5 context");
    }

    if((code = krb5_timeofday(kcontext, &now))) {
	log_error("auth_kdc: %s while getting time of day\n", 
			error_message(code));
	abend("can't get the time of day");
    }

    /* just use the name we give you and default domain */
    if ((code = krb5_parse_name (kcontext, username, &me))) {
	 log_error("auth_kdc: ABEND %s when parsing name %s\n", 
			error_message(code), username);
	 abend("krb5 can't parse username");
    }
    
    if ((code = krb5_unparse_name(kcontext, me, &client_name))) {
	log_error("auth_kdc: %s when unparsing name\n", 
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
	log_error("auth_kdc: %s while building kserver name\n", 
			error_message(code));
	return(FAIL);
    }
	
    my_creds.server = kserver;

    my_creds.times.starttime = 0;	/* start timer when request
					   gets to KDC */
    my_creds.times.endtime = now + lifetime;

    my_creds.times.renew_till = 0;

    code = krb5_get_in_tkt_with_password(kcontext, options, addrs,
					      NULL, preauth, passwd, 0,
					      &my_creds, 0);

    memset(passwd, 0, sizeof(passwd));
    
    if (code) {
	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	    log_message("auth_kdc: Password incorrect username: %s\n", 
			username);
	else 
	    log_message("auth_kdc: %s while checking credntials username: %s\n",
			error_message(code), username);
	ret = FAIL;
    }

    /* my_creds is pointing at server */
    krb5_free_principal(kcontext, kserver);

    krb5_free_context(kcontext);
    
    return(ret);

}

//rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr


int main(argc,argv)
int argc;
char **argv;
{
  char   buf[1024];
  char   name[9], prn[7], junk[20];
  int    i;

  printf("want: name <userid> pass <password>\n");

  while ( fgets(buf, 1024, stdin) ) {
      sscanf (buf, "%s", junk);
      if ( ! strcmp(junk, "exit") ) break;
      i=sscanf (buf, "name %s pass %s", name, prn);
//      printf ("\ti ->%d<- name ->%s<- prn ->%s<-\n", i, name, prn);

      ( i == 2 ) ?
          check_login_uwnetid(name,prn) == CHECK_LOGIN_RET_SUCCESS ? printf("auth ok\n") : printf("auth fail\n")
      :
          printf("didn't get what i wanted\n");
      *prn='\0'; *name='\0';
  }

  exit(0);

}

