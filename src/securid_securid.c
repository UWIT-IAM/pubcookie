/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
 $Id: securid_securid.c,v 1.8 2003-05-06 23:51:19 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#include "index.cgi.h"

#include "li-access.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#define MSGM_MARKER	0xfe

#define MSGT_VALIDATE	0
#define MSGT_NEXT	2
#define MSGT_HEARTBEAT	4

#define MSGR_GOOD	htons(0)
#define MSGR_BAD	htons(1)
#define MSGR_NEXT	htons(2)

#define MSG_TEXTLEN	(20+1+6+1)

typedef struct {
  unsigned char  msgmarker;
  unsigned char  msgtype;
  unsigned short msgrequest;
  unsigned short msgtextlen;
  unsigned short msgresult;
           char  msgtext[MSG_TEXTLEN];
} MSG;

#define MSG_HEADLEN	(sizeof(MSG)-MSG_TEXTLEN)

char *get_clist();

int server(char *, char *, int, int);
int getserver(char *, char*, int, int, int);

int securid(name,prn)
char *name;
char *prn;
{

  int    i, n, fd, doing_type;
  char   *s, *t, *list, crn[20];
  MSG    msg;

  /*
  **  Connect to the smart card server processor.
  */

  s = "smart";

  if ((fd = server("smart",s,1023,0)) < 0) {
    log_error("Unable to connect to server.\n");
    return(-2);
  }

  /*
  **  Find the card name for this person or people.  If multiple cards
  **  are allowed, they'll have to type in the name of the card they're
  **  using or an abbreviation or an abbreviation of an alias.
  */

  /* ssw modified get_clist for return value */
  if ( (list = get_clist(name)) < 0 ) {
    log_error("Problem getting clist.\n");
    return(-2);
  }
  else if (!list ) {
    log_message("eac_securid: No card list for %s.\n", name);
    close(fd);
    return(1);
  }

  s = list;
  t = crn;
  while (t < crn+sizeof(crn) && *s && !isspace(*s)) {
    if (*s == '=') {
      t = crn;
      s++;
    } else {
      *t++ = *s++;
    }
  }
  *t = '\0';

  doing_type = MSGT_VALIDATE;

  if ( (s = (char *)index(prn,'\n'))) *s = '\0';


  /*
  **  Encode a request block and send it to the server.
  */

  sprintf(msg.msgtext,"%s%cxxxx%c%6.6d",crn,0,0,atoi(prn));
  n = strlen(crn) + 1 + 4 + 1 + 6 + 1;

  msg.msgmarker  = MSGM_MARKER;
  msg.msgtype    = doing_type;
  msg.msgrequest = 0;
  msg.msgtextlen = htons(n);
  msg.msgresult  = htons(7);

  n = MSG_HEADLEN + n;
  if ((i = write(fd,&msg,n)) != n) {
    log_message("Tried to write %d, got %d.\n",n,i);
    if (i < 0) {
      perror("eac_securid: securid: write");
    }
    close(fd);
    return(-2);
  }

  if ((i = read(fd,&msg,sizeof(msg))) <= 0) {
    log_message("Got %d: ",i);
    perror("eac_securid: securid: read");
    close(fd);
    return(-2);
  }

  if (i != MSG_HEADLEN) {
    log_message("Funny size of %d instead of %d.\n",i,MSG_HEADLEN);
    close(fd);
    return(1);
  }

  i = msg.msgresult;

  if (i == MSGR_GOOD) {
    close(fd);
    return(0);

  } else if (i == MSGR_BAD) {
    log_message("eac_securid: Bad entry: id=%s, crn=%s, prn=%s.",name,crn,prn);
    close(fd);
    return(1);

  } else if (i == MSGR_NEXT) {
    log_message("eac_securid: Asking for next prn: id=%s, crn=%s, prn=%s.",
							name,crn,prn);
    close(fd);
    return(-1);

  } else {
    log_message("eac_securid: Got garbage back: id=%s, crn=%s, prn=%s, reply=%d.\n",
						name,crn,prn,ntohs(i));
    close(fd);
    return(1);
  }

}

/**********************************************************************/

char *get_clist(id,logflag)
char *id;
{

  /*
  **  Get the list of allowable cards for this id.
  */

/* unused */
/*  char *s; */
  static char line[1024];
  FILE *fp;
  int  fd;


  /*
  **  First we try to get the card name list from the li server.
  */

  if ((fd = getserver("li","li",1023,logflag,1)) >= 0) {

    if (!(fp = fdopen(fd,"r+"))) {
      perror("securid_securid: get_clist: fdopen");
      return((char *)-1);
    }

    sprintf(line,"access %s; user ssu; getcrn id=%s seq=71\nend\n",LI_READ,id);
    if (write(fd,line,strlen(line)) < 0) {
      perror("securid_securid: get_clist: li write");
      return((char *)-1);
    }

    while (fgets(line,sizeof(line),fp)) {
      if (!strncmp(line,"nak",3)) {
	log_message("securid_securid: get_clist: %s", line);
      } else if (!strncmp(line,"ack seq=71",10)) {
	char *s, *t;
        if ((s = (char *)index(line,'(')) && (t = (char *)index(s,')'))) {
	  *t = '\0';
	  fclose(fp);
	  return(++s);
        }
      }
    }

    fclose(fp);
    log_error("eac_securid: No crn found in li reply.\n");

  } else {
    log_error("eac_securid: Unable to communicate with li server.\n");
    return((char *)-1);

  }

  return(0);

}
