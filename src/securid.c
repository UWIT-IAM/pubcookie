/* -------------------------------------------------------------------- */
/* $Id: securid.c,v 1.2 2000-09-08 19:22:08 willey Exp $

   function: securid  
   args:     reason - points to a reason string
             user - the UWNetID
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

int securid (char *reason, char *user, char *s_prn, int log, int typ, int doit)
{
      /* use stderr for blather info */
      FILE *ouf = stderr;
      char **vec, *lst, crn[33], tmp[33];
      int  i, prn, ret;
      char tmp_res[1000];

      vec = NULL; lst = NULL; ret = 0; *crn = ESV; prn = EIV;

      /* move prn if we got one */
      if ( s_prn == NULL ) {
         fprintf (ouf, "No PRN, bye\n");
         reason = strdup("No PRN");
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
         snprintf(tmp_res, 999, "Connect error: %d %s.", MGOerrno, MGOerrmsg);
         syslog (LOG_ERR, "%s\n", tmp_res);
         fprintf (ouf, "%s\n", tmp_res);
         reason = strdup(tmp_res);
         securid_cleanup();
         return(SECURID_PROB);
      }

      if (MGOgetcrn (&lst, user) < 1) {
         snprintf(tmp_res, 999, "No card list for %s.", user);
         if (log) syslog (LOG_WARNING, "%s\n", tmp_res);
         fprintf (ouf, "%s\n", tmp_res);
         reason = strdup(tmp_res);
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
            snprintf(tmp_res, 999, "Trouble finding CRN: field %s", *vec);
            fprintf (ouf, "%s\n", tmp_res);
            reason = strdup(tmp_res);
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
          snprintf(tmp_res, 999, "no securid check was done for user: %s crn: %s", user, crn);
          fprintf (ouf, "%s\n", tmp_res);
          reason = strdup(tmp_res);
          securid_cleanup();
          return(SECURID_BAILOUT);
      }

      if (MGOsidcheck (user, crn, prn, typ) < 1) {
         if (MGOerrno == MGO_E_NPN) {
            snprintf(tmp_res, 999, "Asking for next prn: id=%s, crn=%s, prn=%d.", user, crn, prn);
            if(log) syslog (LOG_INFO, "%s", tmp_res);
            ret = SECURID_WANTNEXT;
         } else if (MGOerrno == MGO_E_CRN) {
            snprintf(tmp_res, 999, "Failed SecurID check: id=%s, crn=%s, prn=%d.", user, crn, prn);
            if(log) syslog (LOG_INFO, "%s", tmp_res);
            if(log) fprintf (ouf, "%s\n", tmp_res);
            ret = SECURID_FAIL;
         } else {
            snprintf(tmp_res, 999, "Unexpected error: %d %s.", 
			MGOerrno, MGOerrmsg);
            syslog (LOG_ERR, "%s\n", tmp_res);
            fprintf (ouf, "%s\n", tmp_res);
            ret = SECURID_PROB;
         }
      } else {
         snprintf(tmp_res, 999, "OK SecurID check: id=%s, crn=%s", user, crn);
         if(log) syslog (LOG_INFO, "%s", tmp_res);
         ret = SECURID_OK;
      }
 
      reason = strdup(tmp_res);
      securid_cleanup();
      return(ret);

}
