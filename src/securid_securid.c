/*
 $Id:
 */


#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>

#include "li-access.h"

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
extern int test_mode;

int securid(name,prn,logflag)
char *name;
char *prn;
int  logflag;
{

  int    i, n, fd, doing_type;
  char   *s, *t, *list, crn[20];
  MSG    msg;

  /*
  **  Connect to the smart card server processor.
  */

  s = test_mode ? "smart_test" : "smart";

  if ((fd = server("smart",s,1023,logflag)) < 0) {
    fprintf(stderr,"Unable to connect to server.\n");
    return(1);
  }

  /*
  **  Find the card name for this person or people.  If multiple cards
  **  are allowed, they'll have to type in the name of the card they're
  **  using or an abbreviation or an abbreviation of an alias.
  */

  if (!(list = get_clist(name,logflag))) {
    if (logflag) syslog(LOG_WARNING,"eac_securid: No card list for %s.\n",name);
//    fprintf(stderr,"No authorization.\n");
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

/*
printf("CRN: %s\tPRN: %s\n", crn, prn);
 */

  if (s = (char *)index(prn,'\n')) *s = '\0';


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
    fprintf(stderr,"Tried to write %d, got %d.\n",n,i);
    if (i < 0) {
      perror("write");
    }
    close(fd);
    return(1);
  }

  if ((i = read(fd,&msg,sizeof(msg))) <= 0) {
    fprintf(stderr,"Got %d: ",i);
    perror("read");
    close(fd);
    return(1);
  }

  if (i != MSG_HEADLEN) {
    fprintf(stderr,"Funny size of %d instead of %d.\n",i,MSG_HEADLEN);
    close(fd);
    return(1);
  }

  i = msg.msgresult;

  if (i == MSGR_GOOD) {
    close(fd);
    return(0);

  } else if (i == MSGR_BAD) {
    if (logflag) 
      syslog(LOG_INFO,"eac_securid: Bad entry: id=%s, crn=%s, prn=%s.",name,crn,prn);
    close(fd);
    return(1);

  } else if (i == MSGR_NEXT) {
    if (logflag) syslog(LOG_INFO,"eac_securid: Asking for next prn: id=%s, crn=%s, prn=%s.",
							name,crn,prn);
//    printf("Enter next PRN: \n");
    close(fd);
    return(1);

  } else {
    if (logflag)
      syslog(LOG_ERR, "eac_securid: Got garbage back: id=%s, crn=%s, prn=%s, reply=%d.\n",
						name,crn,prn,ntohs(i));
    fprintf(stderr,"Unrecognized result %d.\n",ntohs(i));
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

  char *s;
  static char line[1024];
  FILE *fp;
  int  fd;


  /*
  **  First we try to get the card name list from the li server.
  */

  if ((fd = getserver("li","li",1023,logflag,1)) >= 0) {

    if (!(fp = fdopen(fd,"r+"))) {
      perror("fdopen");
      exit(1);
    }

    sprintf(line,"access %s; user ssu; getcrn id=%s seq=71\nend\n",LI_READ,id);
    if (write(fd,line,strlen(line)) < 0) {
      perror("li write");
      exit(1);
    }

    while (fgets(line,sizeof(line),fp)) {
      if (!strncmp(line,"nak",3)) {
//	fprintf(stderr,line);
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
//    fprintf(stderr,"No crn found in li reply.\n");

  } else {

    fprintf(stderr,"Unable to communicate with li server.\n");

  }

  return(0);

}
