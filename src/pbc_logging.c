
#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

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

#include "libpubcookie.h"
#include "pbc_myconfig.h"
#include "pbc_logging.h"

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

void pbc_log_init()
{

/* open syslog - we are appending the PID to the log, and prepending 
 * the string "pubcookie login server" to make it easily greppable.
 * Presumably will do something else if we support a logging method other than
 * syslog.. :)
 */

    openlog("pubcookie login server", LOG_PID, LOG_AUTHPRIV);
}


void pbc_log_activity(int logging_level, const char *message,...)
{
    va_list   args;

    va_start(args, message);

    pbc_vlog_activity( logging_level, message, args );

    va_end(args);
}

char * mystrdup( const char * s ) {
    if (s != NULL) return (char *) strdup(s);
    else return NULL;
}

void pbc_vlog_activity( int logging_level, const char * format, va_list args )
{
    char      log[PBC_4K];

    if (logging_level <= (libpbc_config_getint("logging_level", logging_level)))    {

        int pri = LOG_INFO;
        int fac = PBC_LOG_GENERAL_FACILITY;

        char * facstr = mystrdup(libpbc_config_getstring( "general_facility", NULL ));

        vsnprintf(log, sizeof(log)-1, format, args);
        
        if (logging_level == PBC_LOG_ERROR)
            pri = LOG_ERR;
        else if (logging_level == PBC_LOG_AUDIT) {
            if (facstr != NULL) {
                free(facstr);
            }

            fac = PBC_LOG_AUDIT_FACILITY;
            facstr = mystrdup(libpbc_config_getstring( "audit_facility", NULL ));
        }

        if (facstr != NULL) {
            const CODE *c;

            if (isdigit(*facstr))
                fac = atoi(facstr);
            else {
                for (c = facilitynames; c->c_name != NULL; c++)
                    if (strcasecmp(facstr, c->c_name) == 0)
                        fac = c->c_val;
            }
            free(facstr);
        }
        syslog( LOG_MAKEPRI(LOG_FAC(fac),pri), "%s", log );
    }
}

void pbc_log_close()
{
  closelog();
}

#if 0
char* pbc_create_log_message(char *info, char* user, char* app_id)
{
  return sprintf(%s: user ip: %s \t app id: %s \n %s, 
libpbc_time_string(time(NULL)),user,app_id, info);
  
}
#endif
