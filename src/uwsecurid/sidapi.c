/*--------------------------------------------------------------------
      sidapi.c -- SecurID API interface routines
  --------------------------------------------------------------------*/

/* The following routines are defined:
 *
 * int  PROC SIDallocmem (void **, int, int);
 * int  PROC SIDconnect (SidHandle *);
 * void PROC SIDdisconnect (SidHandle *);
 * char PROC *SIDerrormsg (int);
 * void PROC SIDfreehandle (SidHandle *);
 * void PROC SIDfreemem (void *);
 * int  PROC SIDgetoption (SidHandle *, int, void **);
 * int  PROC SIDinitialize (SidHandle **, char *);
 * int  PROC SIDsetoption (SidHandle *, int, void *);
 * int  PROC SIDstrdup (char **, char *, int);
 * int  PROC SIDstrtol (int *, char *, int);
 * int  PROC SIDvalidate (SidHandle *, char *, int, int);
 */

#include "sidapi.h"
#include "messages.h"

#include <time.h>
#include <sys/time.h>

#ifdef UNIX
#  include <sys/poll.h>
#  include <sys/time.h>
#  define socket_errno errno
#endif
#ifdef WIN32
#  define socket_errno WSAGetLastError()
#  define sleep(x) Sleep((x) * 1000) 
#endif

typedef struct HostList_
{
   struct HostList_ *next;              /* Next entry */
   char *host;                          /* Name */
   int  port;                           /* Port */
   struct sockaddr_in sock;             /* Socket address */
} HostList;

typedef struct SecurData_
{
   unsigned char  marker;               /* Data marker */
   unsigned char  mode;                 /* Validation mode */
   unsigned short request;              /* Request value */
   unsigned short textlen;              /* Length of request text */
   unsigned short result;               /* Result value */
   char text[28];                       /* Request text */
} SecurData;

#define eol(i) ((i) + strlen ((i)))
#define isconnected(i) ((i)->fd != -1)
#define match(i,j) (strcasecmp ((i), (j)) == 0)

/*--------------------------------------------------------------------
      freehostlist -- Free a HostList struct
  --------------------------------------------------------------------*/

static void PROC freehostlist (HostList *list)
{
      HostList *cur, *nxt;

      for (cur = list; cur != NULL; cur = nxt) {
         nxt = cur->next;
         SIDfreemem ((void *) cur->host);
         SIDfreemem ((void *) cur);
      }

      return;
}

/*--------------------------------------------------------------------
      getdata -- Read input from descriptor
  --------------------------------------------------------------------*/

static int PROC getdata (int fd, char *strn, int nch, int tmo)
{
      struct pollfd pfd;
      int len, rets;

      pfd.fd = fd; pfd.events = POLLIN | POLLPRI;
      len = nch; nch = 0;

      while (len > 0) {
         if ((rets = poll (&pfd, 1, tmo)) > 0) {
            if ((rets = read (fd, strn + nch, len)) < 1) {
               if (rets == 0) break;
               return (rets);
            }
            nch += rets; len -= rets;
         } else {
            return (0);
         }
      }

      if (nch >= 0) strn[nch] = '\0';
      return (nch);
}

/*--------------------------------------------------------------------
      getline -- Get input from file
  --------------------------------------------------------------------*/

static int PROC getline (char *strn, int size, FILE *fd)
{
      char *p = strn, *s = strn;

      while (fgets (p, size, fd) != NULL) {
         if (*p == '\n' || *p == '#' || *p == '!') continue;
         s = &p[strlen (p) - 1];
         if (s - 1 < p || *(s - 1) != '\\') break;
         size -= s - p; p = s - 1; 
      }

      *s = '\0';
      return (s - strn);
}

/*--------------------------------------------------------------------
      putdata -- Write output to descriptor
  --------------------------------------------------------------------*/

static int PROC putdata (int fd, char *strn, int nch)
{
      int len, rets;

      len = nch; nch = 0;

      while (len > 0) {
         if ((rets = write (fd, strn + nch, len)) < 1) {
            if (rets == 0) break;
            return (rets);
         }
         nch += rets; len -= rets;
      }

      return (nch);
}

/*--------------------------------------------------------------------
      parsestr -- Parse token from string
  --------------------------------------------------------------------*/

static int PROC parsestr (char *strn, int *posn, char **tokn, int kase)
{
      char *s, *t;
      int  rets;

      if (strn != NULL) {
         for (s = strn + *posn; *s && strchr (" \f\n\r\t\v", *s) != NULL; s++);
         if (kase == 2) {
            for (t = s, s = eol (t); s != t; s--) {
               if (*s == '\0' || strchr (" \f\n\r\t\v", *s) == NULL) break;
            }
         } else {
            for (t = s; *s != '\0'; s++) {
               if (*s == '\0' || strchr (" \f\n\r\t\v", *s) != NULL) break;
            }
         }
         if (tokn != NULL) *tokn = NULL;
         if (s != t) {
            if (tokn != NULL) {
               if ((rets = SIDallocmem ((void **) tokn, s - t + 1, 0)) == SID_SUCCESS) {
                  memcpy (*tokn, t, s - t);
               }
            } else {
               rets = SID_SUCCESS;
            }
            *posn = s - strn + (*s ? 1 : 0);
         } else {
            rets = SID_NO_MORE_TOKENS;
         }
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}

/*--------------------------------------------------------------------
      genhostlist -- Generate list of directory hosts
  --------------------------------------------------------------------*/

static int PROC genhostlist (HostList **list, SidHandle *hndl)
{
      struct hostent *hp, *hr;
      HostList *curh, *newh;
      char **addr, *name, *sepr;
      int port, posn, rets;

      posn = rets = 0;

      while (parsestr (hndl->host ? hndl->host : SID_HOST, &posn, &name, 1) == SID_SUCCESS) {
         if ((sepr = strstr (name, ":")) != NULL) {
            *sepr = '\0';
            port = atoi (sepr + 1);
         } else {
            if (hndl->port == 0) {
               port = SID_PORT;
            } else {
               port = hndl->port;
            }
         }
         if ((hp = gethostbyname (name)) != NULL) {
            for (addr = hp->h_addr_list; *addr != NULL; addr++) {
               if ((rets = SIDallocmem ((void **) &newh, sizeof (HostList), 0)) == SID_SUCCESS) {
                  if (*list != NULL) {
                     curh->next = newh; curh = newh;
                  } else { 
                     *list = curh = newh;
                  }
                  memcpy (&newh->sock.sin_addr, *addr, hp->h_length);
                  newh->sock.sin_family = AF_INET; 
                  newh->sock.sin_port = htons (port);
               }
            }
         } else {
            rets = -socket_errno;
         }
         SIDfreemem ((void *) name);
      }

      if (rets == SID_SUCCESS) {
         for (curh = *list; curh != NULL; curh = curh->next) {
            if ((hp = gethostbyaddr (&curh->sock.sin_addr, sizeof (curh->sock.sin_addr), AF_INET)) != NULL) {
               rets = SIDstrdup (&curh->host, hp->h_name, 0);
            } else {
               rets = SIDstrdup (&curh->host, inet_ntoa (curh->sock.sin_addr), 0);
            }
            curh->port = ntohs (curh->sock.sin_port);
         }
      }

      return (rets);
}

/*--------------------------------------------------------------------
      initialize -- Process initialization file
  --------------------------------------------------------------------*/

static int PROC initialize (SidHandle *hndl, char *conf)
{
      FILE *fd;
      char buff[512], *name, *valu;
      int  posn, rets;

      rets = SID_SUCCESS;

      if ((fd = fopen (conf, "r")) != NULL) {
         while (rets == SID_SUCCESS && getline (buff, sizeof (buff) - 1, fd) > 0) {
            posn = 0;
            if (parsestr (buff, &posn, &name, 1) == SID_SUCCESS && parsestr (buff, &posn, &valu, 2) == SID_SUCCESS) {
               if (match (name, "host")) {
                  rets = SIDstrdup (&hndl->host, (char *) valu, 1);
               } else if (match (buff, "includefile")) {
                  rets = initialize (hndl, valu);
               } else if (match (name, "marker")) {
                  rets = SIDstrtol (&hndl->marker, (char *) valu, 0);
               } else if (match (name, "port")) {
                  rets = SIDstrtol (&hndl->port, (char *) valu, 0);
               }
            }
            SIDfreemem ((void *) name);
            SIDfreemem ((void *) valu);
         }
         fclose (fd);
      } else if (errno != ENOENT) {
         rets = -(errno);
      }

      return (rets);
}

/*--------------------------------------------------------------------
      reconnect -- Maintain connection to server
  --------------------------------------------------------------------*/

static int PROC reconnect (SidHandle *hndl, int *try)
{
      int rets;

      while ((*try)++ < 5) {
         if ((rets = SIDconnect (hndl)) == SID_SUCCESS) return (rets);
         sleep (1);
      }

      return (rets);
}

/*--------------------------------------------------------------------
      SIDallocmem -- Allocate and zero out memory
  --------------------------------------------------------------------*/

int PROC SIDallocmem (void **mem, int size, int flag)
{
      size = (size / 4 + 1) * 4 + 1;

      if (flag && *mem) {
         *mem = (void *) realloc (*mem, size);
      } else {
         if ((*mem = (void *) malloc (size)) != NULL) {
            memset (*mem, 0, size);
         }
      }

      return (*mem ? SID_SUCCESS : SID_ENOMEM);
}

/*--------------------------------------------------------------------
      SIDconnect -- Connect to server
  --------------------------------------------------------------------*/

int PROC SIDconnect (SidHandle *hndl)
{
      HostList *list, *h;
      char name[255];
      int  rets;

      list = NULL; rets = SID_SUCCESS;

      if (hndl != NULL) {
         if (!isconnected (hndl)) {
            if ((rets = genhostlist (&list, hndl)) == SID_SUCCESS) {
               rets = SID_SERVER_UNAVAIL;
               for (h = list; h != NULL && rets == SID_SERVER_UNAVAIL; h = h->next) {
                  if ((hndl->fd = socket (AF_INET, SOCK_STREAM, 0)) >= 0) {
                     if (connect (hndl->fd, (struct sockaddr *) &h->sock, sizeof (h->sock)) == 0) {
                        snprintf  (name, sizeof (name), "%s:%d", h->host, h->port);
                        SIDstrdup (&hndl->server, name, 0);
                        break;
                     } else if (errno != ECONNREFUSED) {
                        rets = -socket_errno;
                     }
                  } else {
                     rets = -socket_errno;
                  }
                  SIDdisconnect (hndl);
               }
               freehostlist (list);
            }
         }
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}

/*--------------------------------------------------------------------
      SIDdisconnect -- Disconnect from server
  --------------------------------------------------------------------*/

int PROC SIDdisconnect (SidHandle *hndl)
{
      int rets;

      if (hndl != NULL) {
         if (isconnected (hndl)) {
            close (hndl->fd); SIDfreemem ((void *) hndl->server);
            hndl->fd = -1; hndl->server = NULL;
         }
         rets = SID_SUCCESS;
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}

/*--------------------------------------------------------------------
      SIDerrormsg -- Turn error code into message string
  --------------------------------------------------------------------*/

char PROC *SIDerrormsg (int code)
{
      static char text[255];

      if (code >= 0) {
         if (code < ERR_MSGS_MAX) {
            strncpy (text, _err_msgs[code], sizeof (text) - 1);
         } else {
            snprintf (text, sizeof (text) - 1, "Unknown error %d", code);
         }
      } else {
         strncpy (text, strerror (-code), sizeof (text) - 1);
      }

      return (text);
}

/*--------------------------------------------------------------------
      SIDfreehandle -- Free an SidHandle struct
  --------------------------------------------------------------------*/

void PROC SIDfreehandle (SidHandle *hndl)
{
      if (hndl) {
         SIDdisconnect (hndl);
         SIDfreemem ((void *) hndl->config);
         SIDfreemem ((void *) hndl->host);
         SIDfreemem ((void *) hndl->server);
         SIDfreemem ((void *) hndl);
      }

      return;
}

/*--------------------------------------------------------------------
      SIDfreemem -- Free allocated memory
  --------------------------------------------------------------------*/

void PROC SIDfreemem (void *mem)
{
      if (mem) free (mem);
      return;
}

/*--------------------------------------------------------------------
      SIDgetoption -- Get option from handle
  --------------------------------------------------------------------*/

int PROC SIDgetoption (SidHandle *hndl, int optn, void **text)
{
      int rets;

      rets = SID_SUCCESS;

      if (hndl != NULL && text != NULL) {
         switch (optn) {
            case SID_OPT_CONFIG:
               rets = SIDstrdup ((char **) text, hndl->config, 0);
               break;
            case SID_OPT_HOST:
               rets = SIDstrdup ((char **) text, hndl->host, 0);
               break;
            case SID_OPT_MARKER:
               *text = (int *) hndl->marker;
               break;
            case SID_OPT_PORT:
               *text = (int *) hndl->port;
               break;
            case SID_OPT_SERVER:
               rets = SIDstrdup ((char **) text, hndl->server, 0);
               break;
            default:
               rets = SID_INVALID_OPTION;
               break;
         }
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}

/*--------------------------------------------------------------------
      SIDinitialize -- Initialize API and settings
  --------------------------------------------------------------------*/

int PROC SIDinitialize (SidHandle **hndl, char *file)
{
      int rets;

      if (hndl != NULL) {
         if (*hndl == NULL || (*hndl)->initial != 86) {
            if ((rets = SIDallocmem ((void **) hndl, sizeof (SidHandle), 0)) == SID_SUCCESS) {
               (*hndl)->initial = 86;
               (*hndl)->fd = -1;
               (*hndl)->marker = SID_MARKER;
            }
         }
         if ((rets = SIDstrdup (&(*hndl)->config, file ? file : SID_CONFIG, 1)) == SID_SUCCESS) {
            rets = initialize (*hndl, (*hndl)->config);
         }
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}

/*--------------------------------------------------------------------
      SIDsetoption -- Set option in handle
  --------------------------------------------------------------------*/

int PROC SIDsetoption (SidHandle *hndl, int optn, void *text)
{
      int *valu, rets;

      rets = SID_SUCCESS;

      if (hndl != NULL && text != NULL) {
         switch (optn) {
            case SID_OPT_CONFIG:
               rets = SIDstrdup (&hndl->config, (char *) text, 1);
               break;
            case SID_OPT_HOST:
               rets = SIDstrdup (&hndl->host, (char *) text, 1);
               break;
            case SID_OPT_MARKER:
               valu = (int *) text; hndl->marker = *valu;
               break;
            case SID_OPT_PORT:
               valu = (int *) text; hndl->port = *valu;
               break;
            default:
               rets = SID_INVALID_OPTION;
               break;
         }
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}

/*--------------------------------------------------------------------
      SIDstrdup -- Duplicate string
  --------------------------------------------------------------------*/

int PROC SIDstrdup (char **dups, char *strn, int flag)
{
      if (flag && *dups) free ((void *) *dups);

      if (strn) {
         *dups = strdup (strn);
      } else {
         *dups = NULL;
      }

      return (*dups || !strn ? SID_SUCCESS : SID_ENOMEM);
}

/*--------------------------------------------------------------------
      SIDstrtol -- Convert string to a number
  --------------------------------------------------------------------*/

int PROC SIDstrtol (int *dups, char *strn, int base)
{
      char *s;

      if (strn) {
         *dups = strtol (strn, &s, base);
      } else {
         *dups = 0;
      }

      return (*dups != LONG_MIN && *dups != LONG_MAX ? SID_SUCCESS : SID_ERANGE);
}

/*--------------------------------------------------------------------
      SIDvalidate --
  --------------------------------------------------------------------*/

int PROC SIDvalidate (SidHandle *hndl, char *crn, int prn, int mode)
{
      SecurData rcv, snd;
      int  nch, resl, rets, try;
 
      try = 0;

      if (hndl != NULL && crn != NULL && (mode == SID_VALIDATE || mode == SID_NEXTPRN)) {
         nch = strlen (crn) + 13;
         sprintf (snd.text, "%s%cxxxx%c%6.6d", crn, 0, 0, prn);
         snd.marker  = hndl->marker;
         snd.mode    = mode;
         snd.request = 0;
         snd.textlen = htons (nch);
         snd.result  = htons (7);
         nch += sizeof (snd) - sizeof (snd.text);
         while ((rets = reconnect (hndl, &try)) == SID_SUCCESS) {
            if (putdata (hndl->fd, (char *) &snd, nch) == nch && getdata (hndl->fd, (char *) &rcv, 8, 15000) == 8) {
               if ((resl = htons (rcv.result)) == 0) {
                  rets = SID_SUCCESS;
               } else {
                  rets = (resl == 2 ? SID_NEXT_PRN_REQD : SID_INVALID_CRN);
               }
               return (rets);
            } else {
               rets = SID_NETWORK_ERROR;
               SIDdisconnect (hndl);
            }
         }
      } else {
         rets = SID_INVALID_ARGUMENT;
      }

      return (rets);
}
