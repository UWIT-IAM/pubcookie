/*
  Copyright (c) 2003 Tim Funk.  All rights reserved.
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file verify_fork.c
 *  Verifier that forks something and uses it to authenticate
 *
 * A verifier which launches another application with 2 
 * arguements, userid and password. The called program will then 
 * set a non-zero exit code if authentication fails. The called program will 
 * exit with 0 status if all is OK.
 *
 * To use verify_fork:
 * a) In your config:  'basic_verifier: verify_fork'
 * b) The application to run is specified by a parameter called "fork_exe", 
 * for example:
 * fork_exe: /usr/local/pubcookie/runme.pl
 *
 * From Tim Funk <funkman@joedog.org> 18-Sept-2003
 *
 * $Id: verify_fork.c,v 1.2 2003-09-24 01:10:45 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif /* HAVE_SYS_WAIT_H */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* Pretending we're Apache */
typedef void pool;

#include "verify.h"
#include "pbc_logging.h"


int verify_fork_v(pool * p,
                  const char *userid,
                  const char *passwd,
                  const char *service,
                  const char *user_realm,
                  struct credentials **creds,
                  const char **errstr)
{
    pid_t pid;
    int status, died;
    char* fork_exe;

    if (errstr) *errstr = NULL;
    if (creds) *creds = NULL;

    pbc_log_activity(p,
                     PBC_LOG_DEBUG_OUTPUT,
                     "verify_fork: enter");

    fork_exe = (char*)libpbc_config_getstring(p, "fork_exe", NULL);

    pbc_log_activity(p,
                     PBC_LOG_DEBUG_VERBOSE,
                     "verify_fork: fork_exe=%s",
                     fork_exe);

    if (!userid) {
       *errstr = "no userid to verify";
       return -1;
    }

    if (!passwd) {
       *errstr = "no password to verify";
       return -1;
    }


    pbc_log_activity(p, PBC_LOG_DEBUG_OUTPUT,
                     "verify_fork: about to fork");

    switch(pid=fork()){
        case -1:
            pbc_log_activity(p, PBC_LOG_ERROR,
                             "verify_fork: Couldn't fork");
            *errstr = "Couldn't fork";
            exit(-1);
        case 0 :
            pbc_log_activity(p, PBC_LOG_DEBUG_OUTPUT,
                             "verify_fork: about to execl");
            execl(fork_exe, fork_exe, userid, passwd, NULL);
            /* Should not occur since execl doesn't return */
            pbc_log_activity(p, PBC_LOG_ERROR,
                             "verify_fork: can't exec, errno=%d", errno);

            exit(-1);
        default:
            pbc_log_activity(p, PBC_LOG_DEBUG_OUTPUT,
                             "verify_fork: about to wait");
            if (-1==waitpid(pid, &status, 0)) {
                pbc_log_activity(p, PBC_LOG_ERROR,
                                 "verify_fork: Wait for child failed");
                *errstr=("Wait for child failed");
                return -2;
            }

            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                             "verify_fork: wait=%d", status);
            if (0==status)
                return 0;

            pbc_log_activity(p,
                             PBC_LOG_DEBUG_OUTPUT,
                             "verify_fork: setting error");
            *errstr=("Non 0 child exit");
            return -1;
    }


}

verifier fork_verifier = { "verify_fork", &verify_fork_v, NULL, NULL };

