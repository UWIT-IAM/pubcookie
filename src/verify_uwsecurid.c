/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file index.cgi.c
 * U Wash SecurID verifier
 *
 *   the U Wash SecurID verifier verifies a username and PRN 
 *   against a U Wash SecurID.  sadly, U Wash SecurID is different
 *   than any other securid you're likely to run into
 *
 *  function: securid  
 *  args:     reason - points to a reason string
 *            user - the UWNetID
 *            card_id - the username for the card
 *            s_prn - the prn
 *            log - deprecieated, 
 *            type - SECURID_TYPE_NORM - normal
 *            doit - SECURID_DO_SID - yes, check prn
 *                   SECURID_ONLY_CRN - no, don't check prn, only report crn
 *
 *   returns:  SECURID_OK - ok
 *             SECURID_FAIL - fail
 *            SECURID_WANTNEXT - next prn
 *            SECURID_PROB - something went wrong
 *            SECURID_BAILOUT - bailed out before sid check, by request
 *  
 *  outputs:  even without log set non-zero there will be some output to
 *
 *   @return 0 on success, -1 if sid lookup fails, -3 next PRN,
 *          -2 on system error
 *
 * $Id: verify_uwsecurid.c,v 2.2 2004-02-10 00:42:15 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* Pretending we're Apache */
typedef void pool;
pool *p = NULL;

#include "verify.h"

#ifdef ENABLE_UWSECURID /* ENABLE_UWSECURID */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

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

#include "pbc_logging.h"

#define SECURID_DO_SID    1
#define SECURID_ONLY_CRN  0
#define SECURID_TYPE_NORM 0

#define SECURID_OK        0
#define SECURID_FAIL      1
#define SECURID_WANTNEXT  2
#define SECURID_PROB      3
#define SECURID_BAILOUT   4

#define BIGS 1024

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

void securid_cleanup() 
{
    MGOdisconnect ();

}

int securid(char *reason, 
            const char *user, 
            const char *card_id, 
            const char *s_prn, 
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
      pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "Securid result: %s", tmp_res);

      /* move prn if we got one */
      if ( s_prn == NULL ) {
         reason = strdup("No PRN");
         pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
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
         reason = strdup(tmp_res);
         pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
         securid_cleanup();
         return(SECURID_PROB);
      }

      if (MGOgetcrn (&lst, (char *)user) < 1) {
         snprintf(tmp_res, BIGS, "No card list for %s.", user);
         reason = strdup(tmp_res);
         pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
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
            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
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
          pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
          securid_cleanup();
          return(SECURID_BAILOUT);
      }

      if (MGOsidcheck ((char *)user, crn, prn, typ) < 1) {
         if (MGOerrno == MGO_E_NPN) {
            snprintf(tmp_res, BIGS, 
		"Asking for next prn: id=%s, crn=%s, prn=%d.", user, crn, prn);
            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
            ret = SECURID_WANTNEXT;
         } else if (MGOerrno == MGO_E_CRN) {
            snprintf(tmp_res, BIGS, 
		"Failed SecurID check: id=%s, crn=%s, prn=%d.", user, crn, prn);
            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
            ret = SECURID_FAIL;
         } else {
            snprintf(tmp_res, BIGS, "Unexpected error: %d %s.", 
			MGOerrno, MGOerrmsg);
            reason = strdup(tmp_res);
            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
            ret = SECURID_PROB;
         }
      } else {
         snprintf(tmp_res, BIGS, "OK SecurID check: id=%s, crn=%s", user, crn);
         pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
         ret = SECURID_OK;
      }
 
      reason = strdup(tmp_res);
      pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
      securid_cleanup();
      return(ret);

}

static int uwsecurid_v(pool * p, const char *userid,
		    const char *sid,
		    const char *service,
		    const char *user_realm,
		    struct credentials **creds,
		    const char **errstr)
{

    char *reason = NULL;  /* dunno about this */
    char *card_id;
    int result;
    char *ptr;
    char *prn = NULL;

    if (!sid) return (-1);

    /* if the securid field is in the form card_id=prn seperate it */
    ptr = card_id = (char *)sid;
    while( *ptr ) {
      if( *ptr == '=' ) {
          *ptr = '\0';
          prn = ++ptr;
      }
      ptr++;
    }
    if( prn == NULL ) {
        card_id = NULL;
        prn = (char *)sid;
    }

    /* what do we do with the card_id? */
    result = securid(reason, 
                     userid, 
                     card_id, 
                     prn, 
                     1, 
                     SECURID_TYPE_NORM, 
                     SECURID_DO_SID);

    switch (result) {
        case SECURID_OK:
            return(0);
            break;
        case SECURID_FAIL:
            return(-1);
            break;
        case SECURID_WANTNEXT:
            return(-3);
            break;
        case SECURID_PROB:
            return(-2);
            break;
        case SECURID_BAILOUT:
            return(-2);
            break;
        default:
            return(-2);
            break;
    }

}

#else /* ENABLE_UWSECURID */

static int uwsecurid_v(pool * p, const char *userid,
		    const char *passwd,
		    const char *service,
		    const char *user_realm,
		    struct credentials **creds,
		    const char **errstr)
{
    if (creds) *creds = NULL;

    *errstr = "U Wash. SecurID verifier not implemented";
    return -1;
}

#endif /* ENABLE_UWSECURID */

verifier uwsecurid_verifier = { "uwsecurid", &uwsecurid_v, NULL, NULL };

