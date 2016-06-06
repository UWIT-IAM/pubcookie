/* ========================================================================
 * Copyright 2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
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
 * $Id: verify_uwsecurid.c,v 2.12 2008-05-16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* Pretending we're Apache */
typedef void pool;
pool *p = NULL;

#include "verify.h"

#ifdef ENABLE_UWSECURID         /* ENABLE_UWSECURID */

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

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_MANGO_H
# include <tasapi3.h>
#endif /* HAVE_MANGO_H */

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

void securid_cleanup (MdsHandle * shndl)
{
    MDSdisconnect (shndl);
    MDSfreehandle (shndl);
}

int securid (char *reason,
             const char *user,
             const char *card_id,
             const char *s_prn, int log, int typ, int doit)
{
    int i, prn, ret;
    char tmp_res[BIGS];
    pbc_time_t date;
    char buff[BSIZ];
    int mode, opts, rets;
    MdsHandle *mds;
    CrnList crn;
    int port = TAS_PORT;
    char *host = TAS_HOST;

    MDSzero (&crn, sizeof (CrnList));
    pbc_time (&date);
    mds = NULL;
    rets = 0;
    snprintf (buff, BSIZ, "%s/%s", "weblogin", user);
    opts = MDS_OPT_CST;

    snprintf (tmp_res, BIGS,
              "user: %s card_id: %s s_prn: %s log: %d typ: %d doit: %d",
              (user ? user : "(NULL)"), (card_id ? card_id : "(NULL)"),
              (s_prn ? s_prn : "(NULL)"), log, typ, doit);
    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "Securid visit: %s",
                      tmp_res);

    /* check we got a  prn */
    if (s_prn == NULL) {
        reason = strdup ("No PRN");
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
        securid_cleanup (mds);
        return (SECURID_PROB);
    }

    strncpy (crn.user, user, 128);
    strncpy (crn.prn, s_prn, 32);
    if (card_id!=NULL) strncpy (crn.crn, card_id, 2048);

    TASinitialize (&mds, NULL);
    MDSsetoption (mds, MDS_OPT_HOST, (void *) host);
    MDSsetoption (mds, MDS_OPT_PORT, (void *) &port);

    if ((rets = TASchktoken (mds, &crn)) == MDS_SUCCESS) {
        snprintf (tmp_res, BIGS, "OK SecurID check: id=%s", user);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
        ret = SECURID_OK;
    } else {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "securid failed");
        ret = SECURID_FAIL;
    }

    securid_cleanup (mds);
    return (ret);

}

static int uwsecurid_v (pool * p, const char *userid,
                        const char *sid,
                        const char *service,
                        const char *user_realm,
                        struct credentials **creds, const char **errstr)
{

    char *reason = NULL;        /* dunno about this */
    char *card_id;
    int result;
    char *ptr;
    char *prn = NULL;

    if (!sid)
        return (-1);

            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "uwsecurid_v: user=%s, sid=%s, service=%s, realm=%s\n", 
                 userid, sid, service, user_realm);

    /* if the securid field is in the form card_id=prn seperate it */
    ptr = card_id = (char *) sid;
    while (*ptr) {
        if (*ptr == '=') {
            *ptr = '\0';
            prn = ++ptr;
        }
        ptr++;
    }
    if (prn == NULL) {
        card_id = NULL;
        prn = (char *) sid;
    }

    /* what do we do with the card_id? */
    result = securid (reason,
                      userid,
                      card_id, prn, 1, SECURID_TYPE_NORM, SECURID_DO_SID);

    switch (result) {
    case SECURID_OK:
        return (0);
        break;
    case SECURID_FAIL:
        return (-1);
        break;
    default:
        return (-2);
        break;
    }

}

#ifdef TEST_UWSECURID

#include "pbc_config.h"
#include "pbc_logging.h"

static void mylog (pool * p, int logging_level, const char *msg)
{
    if (logging_level <= libpbc_config_getint (p, "logging_level", 0)) {
        fprintf (stderr, "%s\n", msg);
    }
}


int main (int argc, char **argv)
{
    char buf[1024];
    char name[9];
    char prn[7], junk[20], card_id[20];
    char *use_card_id;
    int i;
    char *reason;
    int check;

    libpbc_config_init (p, NULL, "uwsecurid");
    pbc_log_init (p, "uwsecurid_test", NULL, &mylog, NULL, NULL);

    if (strstr (*argv, "no_check"))
        check = SECURID_ONLY_CRN;
    else
        check = SECURID_DO_SID;

    printf ("want: name <userid> securid <sid>\n");
    printf ("or    name <userid> securid <sid> card_id <card_id>\n");

    while (fgets (buf, 1024, stdin)) {
        sscanf (buf, "%s", junk);
        if (!strcmp (junk, "exit"))
            break;
        if ((i =
             sscanf (buf, "name %s securid %s card_id %s", name, prn,
                     card_id)) == 0)
            i = sscanf (buf, "name %s securid %s", name, prn);

        printf ("\ti ->%d<- name ->%s<- prn ->%s<- card_id ->%s<-\n",
                i, name, prn, card_id);

        if (i = 2)
            use_card_id = name;
        else
            use_card_id = card_id;

        securid (reason, name, card_id, prn, 1, SECURID_TYPE_NORM, check)
            ? printf ("fail\n") : printf ("ok\n");

        *prn = '\0';
        *name = '\0';
        *card_id = '\0';
    }

    exit (0);

}

#endif /* #ifdef TEST_VERIFY */

#else /* ENABLE_UWSECURID */

static int uwsecurid_v (pool * p, const char *userid,
                        const char *passwd,
                        const char *service,
                        const char *user_realm,
                        struct credentials **creds, const char **errstr)
{
    if (creds)
        *creds = NULL;

    *errstr = "U Wash. SecurID verifier not implemented";
    return -1;
}

#endif /* ENABLE_UWSECURID */

verifier uwsecurid_verifier = { "uwsecurid", &uwsecurid_v, NULL, NULL };


/* fake lsc library functions 
   allows linking with default openssl (no 'IDEA')
   disallows actual use of lsc
 */

#ifdef USE_FAKE_LSC
  
int lsc_errno;
void lsc_errmsg() {}
void lsc_read_keylist() {}
void lsc_new() {}
void lsc_authenticate_peer() {}
void lsc_free_keylist() {}
void lsc_free() {}
void lsc_crypt() {}

#endif
