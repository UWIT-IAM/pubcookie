
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
# include <sys/syslog.h>
#endif /* HAVE_SYSLOG_H */

#include "libpubcookie.h"
#include "pbc_myconfig.h"
#include "pbc_logging.h"

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

void pbc_vlog_activity( int logging_level, const char * format, va_list args )
{
    char      new_message[PBC_4K];
    char      log[PBC_4K];
        
    if (logging_level <= (libpbc_config_getint("logging_level", logging_level)))    {

        int pri = LOG_INFO;
        int fac = PBC_LOG_GENERAL_FACILITY;


        vsnprintf(log, sizeof(log)-1, format, args);
        
        if (logging_level == PBC_LOG_ERROR)
            pri = LOG_ERR;
        else if (logging_level == PBC_LOG_AUDIT)
            fac = PBC_LOG_AUDIT_FACILITY;

        syslog( LOG_MAKEPRI(LOG_FAC(fac),pri), log );
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
