/* -------------------------------------------------------------------- */
/* $Id: securid.c,v 1.1 2000-08-08 00:38:12 willey Exp $

   function: securid  
   args:     user - the UWNetID
             s_prn - the PRN
             log - to extra stuff to stderr and syslog
             type - SECURID_TYPE_NORM - normal
                    SECURID_TYPE_NEXT - next prn was requested
             doit - SECURID_DO_SID - yes, check prn
                    SECURID_ONLY_CRN - no, don't check prn, only report crn

   returns:  SECURID_OK - ok
             SECURID_FAIL - fail
             SECURID_WANTNEXT - next prn
             SECURID_PROB - something went wrong
             SECURID_BAILOUT - bailed out before sid check, by request
   
   outputs:  even without log set non-zero there will be some output to
             syslog and stderr in some conditions.  if log is set to non-zero
             then there will be more messages in syslog and stderr
 */
/* -------------------------------------------------------------------- */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "mgoapi.h"
#include "securid.h"

void securid_cleanup () 
{
    MGOdisconnect ();

}

int securid (char *user, char *s_prn, int log, int typ, int doit)
{
      /* use stdout for blather info */
      FILE *ouf = stdout;
      char **vec, *lst, crn[33], tmp[33];
      int  i, prn, ret;

      vec = NULL; lst = NULL; ret = 0; *crn = ESV; prn = EIV;

      /* move prn if we got one */
      if ( s_prn == NULL ) {
         fprintf (ouf, "No PRN, bye\n");
         securid_cleanup();
         return(SECURID_PROB);
      }
      else {
         prn = atoi(s_prn);
      }

      /* with this set to NULL it doesn't do anything, but we do it anyway */
      MGOinitialize(NULL);

      /*
       * Connect to Mango and query for CRN information
       */

      if (MGOconnect () < 1) {
         syslog (LOG_ERR, "Connect error: %d %s.\n", 
			MGOerrno, MGOerrmsg);
         fprintf (ouf, "Cannot connect to server error %d: %s\n", 
			MGOerrno, MGOerrmsg);
         securid_cleanup();
         return(SECURID_PROB);
      }

      if (MGOgetcrn (&lst, user) < 1) {
         if (log) syslog (LOG_WARNING, "No card list for %s.\n", user);
         fprintf (ouf, "No crn authorization found\n");
         securid_cleanup();
         return(SECURID_PROB);
      }

      /* crn fields are either in the form "key1=value1 key2=value2" or   */
      /* simply "value1".  where one of the keys is the user name         */

      vec = MGOvectorize (lst);
      if( *vec != NULL && *(vec +1) != NULL ) {    /* first form          */
         MGOkeyword (*vec, tmp, sizeof (tmp), 0);
         for( i = 0; strcmp(tmp, user) != 0; i++ )
             MGOkeyword (*(vec+i), tmp, sizeof (tmp), 0);
         if ( MGOvalue (*(vec+i), crn, sizeof (crn), 1) < 0 ) {
            fprintf (ouf, "Trouble finding CRN: field %s\n", *vec);
            securid_cleanup();
            return(SECURID_PROB);
         }
      }
      else {                                       /* second form         */
         strcpy(crn, *vec);
      }

      MGOfreevector (&vec);
      MGOfreechar (&lst);

      /* this is the bail-out option */
      if( doit == SECURID_ONLY_CRN ) {
          fprintf (ouf, "no securid check was done for user: %s crn: %s\n", 
         		user, crn);
          securid_cleanup();
          return(SECURID_BAILOUT);
      }

      if (MGOsidcheck (user, crn, prn, typ) < 1) {
         if (MGOerrno == MGO_E_NPN) {
            if(log) syslog (LOG_INFO, "Asking for next prn: id=%s, crn=%s, prn=%d.", user, crn, prn);
            ret = SECURID_WANTNEXT;
         } else if (MGOerrno == MGO_E_CRN) {
            if(log) syslog (LOG_INFO, "Failed SecurID check: id=%s, crn=%s, prn=%d.", user, crn, prn);
            if(log) fprintf (ouf, "Foo, you are nothing but a charlatan!\n");
            ret = SECURID_FAIL;
         } else {
            syslog (LOG_ERR, "Unexpected error: %d %s.\n", MGOerrno, MGOerrmsg);
            fprintf (ouf, "Unexpected error: %d %s\n", MGOerrno, MGOerrmsg);
            ret = SECURID_PROB;
         }
      } else {
         if(log) syslog (LOG_INFO, "OK SecurID check: id=%s, crn=%s", user, crn);
         ret = SECURID_OK;
      }
 
      securid_cleanup();
      return(ret);

}
