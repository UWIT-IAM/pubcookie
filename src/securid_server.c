/*
    $Id: securid_server.c,v 1.2 2000-01-12 04:18:34 willey Exp $
     */

#include <unistd.h>
#include <stdlib.h>
#include "index.cgi.h"

#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(AIX) || defined(_IBMR2) || defined(__osf__) || defined(_SEQUENT_)
#include <sys/select.h>
#endif

#define  nentry(x)	(sizeof(x)/sizeof(x[0]))
#define	 SA		(struct sockaddr *)

#ifdef _XOPEN_SOURCE_EXTENDED
typedef size_t  fromlen_t;
#else
typedef int     fromlen_t;
#endif

extern int errno;
int ping(char *, struct sockaddr_in *);

/*
**  Attempt to connect to the specified host.  Return value is the
**  file descriptor of the socket or -1 if unable to connect.
*/

int getserver(base,service,port,logflag,ro)
char *base;		/* Server.u base name */
char *service;          /* Internet service name */
int  port;		/* Reserved port to use if non-zero */
int  logflag;		/* Debugging/logging flag */
int ro;                 /* true if read-only access needed */
{

  struct sockaddr_in sa_in;  /* Socket address in internet style */
  register struct hostent *host = 0;
  char host_name[256];

  int      i, r, start, try_back, sock=0, do_dgram_prep;
  fromlen_t  len;
  char     buf[80];
  struct   servent *sp;
  struct   timeval timeout;
  fd_set   fds;

  /*
  **  These things don't change, putting them here makes it easier on
  **  us since they don't really need to be in /etc/services on every
  **  system in the world.
  */

  static struct {
    char *name;
    int  port;
  } services[] = {	{"li", 605},		{"smart", 915}, 
			{"smart_test", 916},	{"tpop", 602} };

  /*
  **  First figure out what kind of server we're connecting to.  Some
  **  answer a datagram to tell us they're there, others we just have
  **  to try to connect to.  This table should be updated if the servers
  **  are updated.
  */

  static char *dgram_servers[] = { "li", "tms", "tpop" };

  do_dgram_prep = 0;
  for (i = 0; i < nentry(dgram_servers); i++) {
    if (!strcmp(service,dgram_servers[i])) {
      do_dgram_prep++;
      break;
    }
  }

  /*
  **  Figure out what service number were talking to.
  */

  sa_in.sin_port = 0;
  if ( (sp = getservbyname(service,"tcp")) ) {
    sa_in.sin_port = sp->s_port;
  } else {
    for (i = 0; i < nentry(services); i++) {
      if (!strcmp(service,services[i].name)) {
        sa_in.sin_port = htons(services[i].port);
        break;
      }
    }
  }

  if (!sa_in.sin_port) {
    fprintf(stderr,"Unknown network service: %s\n",service);
    log_error("eac_securid: Unknown network service: %s", service);
    return(-2);
  }
 
  /*
  **  Attempt to connect to a host
  */
 
  start = 1;

  if (do_dgram_prep) {
    if ((sock = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
      perror("socket");
      exit(1);
    }
#if !defined(_SEQUENT_) && !defined(__alpha__)
  } else {
    if (ping(base,&sa_in) == 0) {
      start = 0;
    }
#endif
  }

  r = 1;
  try_back = 0;
  for (i = start;; i++) {
    if (i > 0) {

      /*
      **  We should try the back door if we found a valid host last time.
      */

      if (try_back) {
	char *cp;
	if ( (cp = strchr(host->h_name,'.')) ) {
	  *cp++ = '\0';
/*	  sprintf(host_name,"%sb.u.washington.edu",cp); */
/* what's with the extra arg? */
	  sprintf(host_name,"%sb.u.washington.edu",host->h_name,cp);
	  host = gethostbyname(host_name);
	}
      }

      /*
      **  Find the address for the host's front door.
      */

      if (!try_back || !host) {
        sprintf(host_name,"%s%d.u.washington.edu",base,r++);
	if ( (host = gethostbyname(host_name)) ) {
	  try_back = 1;
	} else {
	  try_back = 0;
	}
      } else {
	try_back = 0;
      }

      if (host) {
        sa_in.sin_family = host->h_addrtype;
        bcopy(host->h_addr, (caddr_t)&sa_in.sin_addr, host->h_length);
      } else {
        if (i == 1) {
          fprintf(stderr,"%s: unknown host\n", host_name);
          log_error("eac_securid: %s: unknown host", host_name);
          return(-2);
        }
        break;
      }
    }

    if (do_dgram_prep) {

      if (sendto(sock,(ro?"s\n":"p\n"),2,0,SA&sa_in,sizeof(sa_in)) != 2) {
 	if (errno != ENETUNREACH && errno != EHOSTUNREACH &&
                   errno != ECONNREFUSED) {
          perror("sendto");
          exit(1);
	}
      }

    } else {

      if (logflag & 0x40) {
        unsigned char *s = (unsigned char *) &sa_in.sin_addr.s_addr;
        fprintf(stderr,"Trying %s connect to %d.%d.%d.%d.\n",
                                          service,s[0],s[1],s[2],s[3]);
      }
      if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        log_error("eac_securid: %s: socket: %m",service);
      } else {
        struct sockaddr_in sin;

        /*
        **  If the port is non-zero, we have to come in on a trusted
        **  port number less than 1024.
        */

        while (port > 0) {
          sin.sin_family = AF_INET;
          sin.sin_addr.s_addr = 0;
          sin.sin_port = htons((u_short)port);
          if (bind(sock,SA&sin,sizeof(sin)) < 0) {
            if (errno == EADDRINUSE || errno == EADDRNOTAVAIL ||
                errno == ENODEV) {
              port--;
            } else {
              log_error("eac_securid: bind %d: %m",port);
              fprintf(stderr,"Port %d ",port);
              perror("bind");
              return(-2);
            }
          } else {
            break;
          }
        }

        /*
        **  Do the actual connection.
        */

log_error("eac_securid: ready to connect to service %s\n",service);

        if (connect(sock, (struct sockaddr *)&sa_in, sizeof (sa_in)) < 0) {
          log_error("eac_securid: %s: connect: %m",service);
          perror("connect");
        } else {
          break;
        }
        close(sock);
      }
      sock = -2;

    }

  }

  if (do_dgram_prep) {

    /*
    **  Now check to see if we got any "bytes".
    */

    len = sizeof(sa_in);
    do {
      FD_ZERO(&fds);
      FD_SET(sock,&fds);
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
      if (!select(sock+1,&fds,0,0,&timeout)) {
        close(sock);
        return(-1);
      }
      recvfrom(sock,buf,sizeof(buf),0,SA&sa_in,&len);
    } while (ro?(*buf=='x'):(*buf != 'p' && *buf != 'P'));
    close(sock);
    if (logflag & 0x40) {
      unsigned char *s = (unsigned char *) &sa_in.sin_addr.s_addr;
      fprintf(stderr,"Trying %s connect to %d.%d.%d.%d.\n",
                                        service,s[0],s[1],s[2],s[3]);
    }
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      log_error("eac_securid: %s: socket: %m",service);
      return(-2);
    }
    if (connect(sock, (struct sockaddr *)&sa_in, sizeof (sa_in)) < 0) {
      perror("connect");
      log_error("eac_securid: %s: connect: %m",service);
      return(-2);
    }

  }

  return(sock);

}

/*
**  Attempt to connect to the specified host.  Return value is the
**  file descriptor of the socket or -1 if unable to connect.
**
**  This is the old entry without the ro flag
*/

int server(base,service,port,logflag)
char *base;		/* Server.u base name */
char *service;          /* Internet service name */
int  port;		/* Reserved port to use if non-zero */
int  logflag;		/* Debugging/logging flag */
{
   return (getserver(base,service,port,logflag,0));
}
