/*--------------------------------------------------------------------
      sidapi.h -- SecurID API interface definitions
  --------------------------------------------------------------------*/

#ifndef _SIDAPI_H_
#define _SIDAPI_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef UNIX
#  include <ctype.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  define SID_CONFIG  "/usr/local/lib/securid/config"
#endif
#ifdef WIN32
#  include <winsock.h>
#  define SID_CONFIG  "C:\\SecurID\\config"
#endif

#define PROC
#define SID_VERSION  "1.01"             /* Software version level */

#define SID_SUCCESS           0
#define SID_NETWORK_ERROR     1
#define SID_NO_MORE_TOKENS    2
#define SID_INVALID_ARGUMENT  3
#define SID_INVALID_OPTION    4
#define SID_SERVER_UNAVAIL    5
#define SID_INVALID_CRN       6
#define SID_NEXT_PRN_REQD     7
#define SID_EPERM             -EPERM
#define SID_ENOENT            -ENOENT
#define SID_EINTR             -EINTR
#define SID_EIO               -EIO
#define SID_EAGAIN            -EAGAIN
#define SID_ENOMEM            -ENOMEM
#define SID_EACCES            -EACCES
#define SID_ENODEV            -ENODEV
#define SID_ENOTDIR           -ENOTDIR
#define SID_EINVAL            -EINVAL
#define SID_ENFILE            -ENFILE
#define SID_ERANGE            -ERANGE
#define SID_ENETUNREACH       -ENETUNREACH
#define SID_ECONNRESET        -ECONNRESET
#define SID_ETIMEDOUT         -ETIMEDOUT
#define SID_ECONNREFUSED      -ECONNREFUSED

#define SID_VALIDATE          0         /* Validate PRN */
#define SID_NEXTPRN           2         /* Validate next PRN */

#define SID_OPT_CONFIG        1         /* Configuration file name */
#define SID_OPT_HOST          2         /* SecurID host name */
#define SID_OPT_MARKER        3         /* Message marker value */
#define SID_OPT_PORT          4         /* SecurID port number */
#define SID_OPT_SERVER        5         /* Connected SecurID host name:port */

#define SID_HOST              "smart1.u.washington.edu smart2.u.washington.edu"
#define SID_PORT              915
#define SID_MARKER            0xfe

typedef struct SidHandle_
{
   int  fd;                             /* SecurID connection handle */
   char *config;                        /* Configuration file name */
   char *host;                          /* SecurID host name */
   char *server;                        /* Connected SecurID host name:port */
   int  marker;                         /* Message marker value */
   int  port;                           /* SecurID port number */
   int  initial;                        /* Initialization performed? */
} SidHandle;

int  PROC SIDallocmem (void **, int, int);
int  PROC SIDconnect (SidHandle *);
int  PROC SIDdisconnect (SidHandle *);
char PROC *SIDerrormsg (int);
void PROC SIDfreehandle (SidHandle *);
void PROC SIDfreemem (void *);
int  PROC SIDgetoption (SidHandle *, int, void **);
int  PROC SIDinitialize (SidHandle **, char *);
int  PROC SIDsetoption (SidHandle *, int, void *);
int  PROC SIDstrdup (char **, char *, int);
int  PROC SIDstrtol (int *, char *, int);
int  PROC SIDvalidate (SidHandle *, char *, int, int);

#endif /* _SIDAPI_H_ */
