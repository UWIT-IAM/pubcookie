
/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is a stub for testing the kdc stuff in the login cgi

 */

/*
    $Id: uwnetid_stub.c,v 1.3 2001-08-23 17:19:43 willey Exp $
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
void log_error(int grade, const char *service, int self_clearing, const char *format,...)
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

    log_error(0, "test", 0, message);
    exit(0);

}


char *check_login_uwnetid(char *user, char *pass)
{

#ifdef DEBUG
    fprintf(stderr, "check_login_uwnetid: hello\n");
#endif 

    if( auth_kdc(user, pass) == NULL )
        return(CHECK_LOGIN_RET_SUCCESS);
    else
        return(CHECK_LOGIN_RET_FAIL);

}

void clear_error(const char *service, const char *message)
{

}

//rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr


int main(argc,argv)
int argc;
char **argv;
{
  char   buf[1024];
  char   name[128], pass[128], junk[20];
  int    i;

  printf("want: name <userid> pass <password>\n");

  while ( fgets(buf, 1024, stdin) ) {
      sscanf (buf, "%s", junk);
      if ( ! strcmp(junk, "exit") ) break;
      i=sscanf (buf, "name %s pass %s", name, pass);
      printf ("\ti ->%d<- name ->%s<- pass ->%s<-\n", i, name, pass);

      ( i == 2 ) ?
          check_login_uwnetid(name,pass) == CHECK_LOGIN_RET_SUCCESS ? printf("auth ok\n") : printf("auth fail\n")
      :
          printf("didn't get what i wanted\n");
      *pass='\0'; *name='\0';
  }

  exit(0);

}

