/*
    $Id:
     */


/*
**  Ping: Use ICMP "echo" to figure out which host interface is closest.
*/

/* added by steve 11/19/99 for linux5 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/signal.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#define SA	(struct sockaddr *)

#ifdef _XOPEN_SOURCE_EXTENDED
typedef size_t  fromlen_t;
#else
typedef int     fromlen_t;
#endif


#define	MAXWAIT		10	/* max time to wait for response, sec.  */
#define MAXPACKET	4096	/* Maximum icmp packet size		*/

extern int errno;

static int s;			/* Socket file descriptor */
static int ident;		/* Our identifier	  */
static int terminate;		/* Termination flag	  */

/*
**  Define a signal handler so we can get out eventually.
*/

static void
ping_alarm(int sig)
{

  terminate = 1;

}

/*
**  Checksum routine for Internet Protocol family headers (C Version)
*/

static u_short ping_cksum(addr, len)
u_short *addr;
int len;
{
  register int nleft = len;
  register u_short *w = addr;
  register u_short answer;
  register int sum = 0;
  u_short odd_byte = 0;

  /*
   *  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while( nleft > 1 )  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if( nleft == 1 ) {
    *(u_char *)(&odd_byte) = *(u_char *)w;
    sum += odd_byte;
  }

  /*
   * add back carry outs from top 16 bits to low 16 bits
   */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);			/* add carry */
  answer = ~sum;				/* truncate to 16 bits */
  return (answer);
}

/*
** 			P I N G E R
** 
**  Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
**  will be added on by the kernel.  The ID field is our UNIX process ID,
**  and the sequence number is an ascending integer.  The first 8 bytes
**  of the data portion are used to hold a UNIX "timeval" struct in VAX
**  byte-order, to compute the round-trip time.
*/

#define MAXHOST 10

static
void child(char *base)
{
  static u_char outpack[MAXPACKET];
  register struct icmp *icp = (struct icmp *) outpack;
  int i, cc, r, n;
  int datalen;		/* How much data */
/* unused ??? */
/*  register struct timeval *tp = (struct timeval *) &outpack[8]; */
  register u_char *datap = &outpack[8+sizeof(struct timeval)];
  char server[128];
  int  nhost, shost;
  struct sockaddr_in addr[MAXHOST];
  pid_t ppid;

  ppid = getppid();

  icp->icmp_type  = ICMP_ECHO;
  icp->icmp_code  = 0;
  icp->icmp_cksum = 0;
  icp->icmp_seq   = 20;
  icp->icmp_id    = ident;		/* ID */

  datalen = 64-8;
  cc = datalen+8;			/* skips ICMP portion */

  for (i=8; i<datalen; i++)		/* skip 8 for time */
    *datap++ = i;

  /* Compute ICMP checksum here */
  icp->icmp_cksum = ping_cksum( icp, cc );

  nhost = MAXHOST;
  shost = -1;
  terminate = 0;

  while (!terminate) {
    int bad = 0;
    for (r = i = 0; i < nhost; i++) {
      if (i > shost) {
        struct hostent *hp;
        sprintf(server,"%s%d.u.washington.edu",base,++r);
        if ( (hp = gethostbyname(server)) ) {
	  char *cp;
          addr[i].sin_family = hp->h_addrtype;
          bcopy(hp->h_addr, (caddr_t)&addr[i].sin_addr, hp->h_length);
          shost = i;

	  /*
	  **  If we've got room, check for a back door interface that
	  **  we can reach.
	  */

	  if (i+1 < nhost && (cp = strchr(hp->h_name,'.'))) {
	    *cp++ = '\0';
	    sprintf(server,"%sb.%s",hp->h_name,cp);
	    if ( (hp = gethostbyname(server)) ) {
	      addr[i+1].sin_family = hp->h_addrtype;
              bcopy(hp->h_addr, (caddr_t)&addr[i+1].sin_addr, hp->h_length);
	      shost = i+1;
	    }
	  }
        } else if (i == 0) {
          fprintf(stderr,"Unknown host: %s",server);
	  kill(ppid,SIGALRM);
          exit(1);
        } else {
          nhost = i;
          break;
        }
      }
      n = sendto(s, outpack, cc, 0, SA&addr[i], sizeof(struct sockaddr));

      if (n != cc)  {
        if (n < 0 && errno != ENETUNREACH && errno != EHOSTUNREACH) {
	  perror(base);
	}
        bad++;
        if (bad >= nhost) {
          fprintf(stderr,"Unable to ping %s server.\n",base);
	  kill(ppid,SIGALRM);
          exit(1);
        }
      }
    }
    sleep(1);
  }
}

int
ping(char *base, struct sockaddr_in *sin_tcp)
{
  pid_t   pid;
  u_char  packet[MAXPACKET];
  struct  sockaddr_in sin_icmp;


  ident = getpid() & 0xFFFF;

  {
    struct  protoent *proto;

    if ((proto = getprotobyname("icmp")) == NULL) {
      fprintf(stderr, "icmp: unknown protocol\n");
      return 1;
    }

    if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
      perror("ping: socket");
      return 5;
    }
  }

  pid = fork();
  if (pid == 0) child(base);

  signal(SIGALRM,ping_alarm);
  alarm(MAXWAIT);

  for (terminate = 0; !terminate;) {
    int len = sizeof (packet);
    fromlen_t fromlen = sizeof(sin_icmp);
    int cc;

    cc = recvfrom(s, packet, len, 0, SA&sin_icmp, &fromlen);
    if (cc < 0) {
      if (errno == EINTR) continue;
      perror("ping: recvfrom");
      terminate = 1;
      break;
    }

    /*
    **  Validate packet.   This logic is necessary because ALL readers of
    **  the ICMP socket get a copy of ALL ICMP packets which arrive ('tis 
    **  only fair).  This permits multiple copies of this program to be run
    **  without getting confused.
    */

    {
      struct ip *ip;
      register struct icmp *icp;
      int hlen;

      ip = (struct ip *) packet;
      hlen = ip->ip_hl << 2;
      if (cc < hlen + ICMP_MINLEN) {
        continue;
      }
      cc -= hlen;
      icp = (struct icmp *)(packet + hlen);
      if (icp->icmp_type != ICMP_ECHOREPLY || icp->icmp_id != ident)  {
        continue;
      }

    }

    break;

  }

  alarm(0);
  close(s);

  kill(pid,SIGTERM);
  waitpid(pid,NULL,0);

  if (terminate) {
    return 1;
  } else {
    sin_tcp->sin_family = AF_INET;
    sin_tcp->sin_addr   = sin_icmp.sin_addr;
    return 0;
  }
}
