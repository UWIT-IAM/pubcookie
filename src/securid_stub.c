
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
#include "securid.h"
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
/* cgic */
#include <cgic.h>

// extra debugging
FILE	*mirror;

int main(argc,argv)
int argc;
char **argv;
{
  char   buf[1024];
  char   name[9], prn[7], junk[20];
  int    i;

  printf("want: name <userid> securid <sid>\n");

  while ( fgets(buf, 1024, stdin) ) {
      sscanf (buf, "%s", junk);
      if ( ! strcmp(junk, "exit") ) break;
      i=sscanf (buf, "name %s securid %s", name, prn);
//      printf ("\ti ->%d<- name ->%s<- prn ->%s<-\n", i, name, prn);

      ( i == 2 ) ?
          securid(name,prn,0,SECURID_TYPE_NORM,SECURID_DO_SID) ? printf("fail\n") : printf("ok\n")
      :
          printf("fail\n");
      *prn='\0'; *name='\0';
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



