
#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

/* LibC */
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif /* HAVE_STDARG_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif /* HAVE_SYS_UTSNAME_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

/* openssl */
#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

/* krb5  */
#ifdef ENABLE_KRB5
# include <com_err.h>
# include <krb5.h>
#endif

/* securid */
#include "securid.h"
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
#include "snprintf.h"

/* cgic */
#ifdef HAVE_CGIC_H
# include <cgic.h>
#endif /* HAVE_CGIC_H */

#ifdef HAVE_DMALLOC_H
# ifndef APACHE
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */


// extra debugging
FILE	*mirror;

int main(argc,argv)
int argc;
char **argv;
{
  char   buf[1024];
  char   name[9], prn[7], junk[20], card_id[20];
  int    i;
  char   *reason;

  printf("want: name <userid> securid <sid>\n");
  printf("or    name <userid> securid <sid> card_id <card_id>\n");

  while ( fgets(buf, 1024, stdin) ) {
      sscanf (buf, "%s", junk);
      if ( ! strcmp(junk, "exit") ) break;
      if( (i=sscanf (buf, "name %s securid %s card_id %s", name, prn, card_id)) == 0 )
          i=sscanf (buf, "name %s securid %s", name, prn);
      
      printf ("\ti ->%d<- name ->%s<- prn ->%s<- card_id ->%s<-\n", 
		i, name, prn, card_id);

      if( i == 2 ) {
          securid(reason, name, name,prn,1,SECURID_TYPE_NORM,SECURID_DO_SID) 
		? printf("fail\n") : printf("ok\n");
//          securid(reason, name, name,prn,1,SECURID_TYPE_NORM,SECURID_ONLY_CRN)
//		? printf("fail\n") : printf("ok\n");
      }
      else {
          if ( i == 3 )
 //             securid(reason,name,card_id,prn,1,SECURID_TYPE_NORM,SECURID_ONLY_CRN) ? printf("fail\n") : printf("ok\n");
              securid(reason,name,card_id,prn,1,SECURID_TYPE_NORM,SECURID_DO_SID) ? printf("fail\n") : printf("ok\n");
          else
              printf("fail\n");
      }

      *prn='\0'; *name='\0'; *card_id='\0';
  }

  exit(0);

}

void log_message(const char *format, ...)
{
    va_list     args;
    char        new_format[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format), "%s: %s\n",
                        ANY_LOGINSRV_MESSAGE, format);
    vfprintf(stderr, new_format, args);
    va_end(args);

}



