/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_logging.c
 * Logging
 *
 * $Id: pbc_logging.c,v 1.25 2003-07-03 04:25:21 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_SYSLOG_H
# ifndef NEED_SYSLOG_NAMES
#  define SYSLOG_NAMES 1
# endif /* NEED_SYSLOG_NAMES */
# include <syslog.h>
#endif /* HAVE_SYSLOG_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif

#include "libpubcookie.h"
#include "pbc_configure.h"
#include "pbc_myconfig.h"
#include "pbc_logging.h"
#include "snprintf.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#ifdef NEED_SYSLOG_NAMES

typedef struct _code {
    char    *c_name;
    int     c_val;
} CODE;

CODE facilitynames[] =
{
    { "auth", LOG_AUTH },
    { "authpriv", LOG_AUTHPRIV },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
# ifdef LOG_FTP
    { "ftp", LOG_FTP },
# endif /* LOG_FTP */
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
# ifdef INTERNAL_MARK
    { "mark", INTERNAL_MARK },          /* INTERNAL */
# endif /* INTERNAL_MARK */
    { "news", LOG_NEWS },
    { "security", LOG_AUTH },           /* DEPRECATED */
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};

#endif /* NEED_SYSLOG_NAMES */

static void mylog(pool *p, int logging_level, const char *mymsg);

static pbc_open_log *olog = NULL;
static pbc_log_func *logf = &mylog;
static pbc_close_log *clog = NULL;

#if defined (WIN32)
/* xxx is there a better win32 function? */

extern int Debug_Trace;
extern FILE *debugFile;  /* from PubcookieFilter */

static void mylog(pool *p, int logging_level, const char *mymsg)
{
    /* xxx should we prepend the time? */

    OutputDebugString(mymsg);  /* win32 debugging */
    if ( debugFile ) {
        fprintf(debugFile,"%s",buff);
    }
}

#else

static void mylog(pool *p, int logging_level, const char *mymsg)
{
    int pri = LOG_INFO;
    int fac = PBC_LOG_GENERAL_FACILITY;
    const char *facstr = libpbc_config_getstring(p, "general_facility", NULL);

    if (logging_level == PBC_LOG_ERROR) {
        pri = LOG_ERR;
    } else if (logging_level == PBC_LOG_AUDIT) {
        fac = PBC_LOG_AUDIT_FACILITY;
        facstr = libpbc_config_getstring(p, "audit_facility", NULL);
    }

    if (facstr != NULL) {
        /* user has specified a different facility to use */
        if (isdigit(*facstr)) {
            fac = atoi(facstr);
        } else {
            const CODE *c;

            for (c = facilitynames; c->c_name != NULL; c++) {
                if (!strcasecmp(facstr, c->c_name)) {
                    fac = c->c_val;
                    break;
                }
            }
        }
    }

    syslog(LOG_MAKEPRI(LOG_FAC(fac),pri), "%s", mymsg);
}

#endif

void pbc_log_init(pool *p, const char *ident,
                  pbc_open_log *o, pbc_log_func *l, pbc_close_log *c)
{
    /* sigh, prototypes not totally standardized so I need to cast */
    if (!o) o = (pbc_open_log *) &openlog;
    if (!l) l = (pbc_log_func *) &mylog;
    if (!c) c = (pbc_close_log *) &closelog;

    olog = o;
    logf = l;
    clog = c;

    if (!ident) {
        ident = "pubcookie";
    }

    if (olog) {
        /* open syslog - we are appending the PID to the log */
        olog((char *) ident, LOG_PID, LOG_AUTHPRIV);
    }
}


void pbc_log_activity(pool *p, int logging_level, const char *message,...)
{
    va_list args;

    va_start(args, message);

    pbc_vlog_activity(p, logging_level, message, args );

    va_end(args);
}

void pbc_vlog_activity(pool *p, int logging_level, const char * format, va_list args )
{
    char      log[PBC_4K];
        
    if (logging_level <= (libpbc_config_getint(p, "logging_level", logging_level))) {
        /* xxx deal with %m here? */
        vsnprintf(log, sizeof(log)-1, format, args);
        
        logf(p, logging_level, log);
    }
}

void pbc_log_close(pool *p)
{
    if (clog) {
        clog(p);
    }
}

#if 0
char* pbc_create_log_message(pool *p, char *info, char* user, char* app_id)
{
    return sprintf(%s: user ip: %s \t app id: %s \n %s, 
                   libpbc_time_string(p, time(NULL)),user,app_id, info);
}
#endif
