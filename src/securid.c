/* -------------------------------------------------------------------- */
/* $Id: securid.c,v 1.11 2003-03-24 21:28:14 jjminer Exp $

   function: securid  
   args:     reason - points to a reason string
             user - the UWNetID
             card_id - the username for the card
             s_prn - the prn
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

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif /* HAVE_SYSLOG_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_MGOAPI_H
# include <mgoapi.h>
#endif /* HAVE_MGOAPI_H */

#ifdef HAVE_SECURID_H
# include <securid.h>
#endif /* HAVE_SECURID_H */

#include "snprintf.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#define SECURID_TRUE 1

void securid_log(int log, char *string) 
{
    FILE *ouf = stderr;

    if (log == SECURID_TRUE) 
      fprintf(ouf, "securid: %s\n", string);

}

void securid_cleanup() 
{
    MGOdisconnect ();

}

int securid(char *reason, 
            char *user, 
            char *card_id, 
            char *s_prn, 
            int log, 
            int typ, 
            int doit)
{
      char **vec, *lst, tmp[33], crn[33];
      int  i, prn, ret;
      char tmp_res[BIGS];

      vec = NULL; lst = NULL; ret = 0; *crn = ESV; prn = EIV;

      snprintf(tmp_res, BIGS, 
	  "user: %s card_id: %s s_prn: %s log: %d typ: %d doit: %d",
	  user, card_id, s_prn, log, typ, doit);
      securid_log(log, tmp_res);

      /* move prn if we got one */
      if ( s_prn == NULL ) {
         reason = strdup("No PRN");
         securid_log(log, reason);
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
         snprintf(tmp_res, BIGS, "Connect error: %d %s.", MGOerrno, MGOerrmsg);
         syslog (LOG_ERR, "%s\n", tmp_res); /* syslog regardless */
         reason = strdup(tmp_res);
         securid_log(log, reason);
         securid_cleanup();
         return(SECURID_PROB);
      }

      if (MGOgetcrn (&lst, user) < 1) {
         snprintf(tmp_res, BIGS, "No card list for %s.", user);
         if (log == SECURID_TRUE) syslog (LOG_WARNING, "%s\n", tmp_res);
         reason = strdup(tmp_res);
         securid_log(log, reason);
         securid_cleanup();
         return(SECURID_PROB);
      }

      /* crn fields are either in the form                                */
      /* "alias1=crn1 crn2 alias3=crn3 ..." or                            */
      /* simply "crn1".                                                   */
      /* If specified, "card_id" selects first entry that it is a         */
      /* substring of.  If not specified, first crn is used.              */

      vec = MGOvectorize (&vec, lst);

      if (card_id != NULL) {

         for (i = 0; vec[i] != NULL; i++) {
            if (strstr(vec[i], card_id)) {
               if (MGOvalue(vec[i], crn, sizeof(crn), 1) < 0) {
                  MGOkeyname(vec[i], crn, sizeof(crn), 1);
               }
               break;
            }
         }

         /* use default (1st) value */
         if (*crn == ESV) {
            MGOkeyword(*vec, tmp, sizeof (tmp), 0);
            if (MGOvalue(*vec, crn, sizeof(crn), 1) < 0) {
                strcpy(crn, tmp);
            }
         }

         if (*crn == ESV) {
            reason = strdup("Invalid CRN");
            securid_log(log, reason);
            securid_cleanup();
            return SECURID_PROB;
         }

      } else {

         /* Use default (1st) value */

         if (MGOvalue(vec[0], crn, sizeof(crn), 1) < 0) {
            MGOkeyname(vec[0], crn, sizeof(crn), 1);
         }

      }

      MGOfreevector (&vec);
      MGOfreechar (&lst);

      /* this is the bail-out option */
      if( doit == SECURID_ONLY_CRN ) {
          snprintf(tmp_res, BIGS, 
          	"no securid check was done for user: %s crn: %s", user, crn);
          reason = strdup(tmp_res);
          securid_log(log, reason);
          securid_cleanup();
          return(SECURID_BAILOUT);
      }

      if (MGOsidcheck (user, crn, prn, typ) < 1) {
         if (MGOerrno == MGO_E_NPN) {
            snprintf(tmp_res, BIGS, 
		"Asking for next prn: id=%s, crn=%s, prn=%d.", user, crn, prn);
            if(log) syslog (LOG_INFO, "%s", tmp_res);
            ret = SECURID_WANTNEXT;
         } else if (MGOerrno == MGO_E_CRN) {
            snprintf(tmp_res, BIGS, 
		"Failed SecurID check: id=%s, crn=%s, prn=%d.", user, crn, prn);
            if(log) syslog (LOG_INFO, "%s", tmp_res);
            ret = SECURID_FAIL;
         } else {
            snprintf(tmp_res, BIGS, "Unexpected error: %d %s.", 
			MGOerrno, MGOerrmsg);
            syslog (LOG_ERR, "%s\n", tmp_res);
            reason = strdup(tmp_res);
            securid_log(log, reason);
            ret = SECURID_PROB;
         }
      } else {
         snprintf(tmp_res, BIGS, "OK SecurID check: id=%s, crn=%s", user, crn);
         if(log) syslog (LOG_INFO, "%s", tmp_res);
         ret = SECURID_OK;
      }
 
      reason = strdup(tmp_res);
      securid_log(log, reason);
      securid_cleanup();
      return(ret);

}
