#ifndef INCLUDED_PBC_LOGGING_H
#define INCLUDED_PBC_LOGGING_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define PBC_LOG_ERROR 0
#define PBC_LOG_AUDIT 1
#define PBC_LOG_DEBUG_LOW 2
#define PBC_LOG_DEBUG_VERBOSE 3
#define PBC_LOG_DEBUG_OUTPUT 5

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif /* HAVE_STDARG_H */

#ifdef NEED_LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
#endif /* NEED_LOG_AUTHPRIV */

#ifdef NEED_LOG_MAKEPRI
# define LOG_MAKEPRI(fac, pri) fac|pri
#endif /* NEED_LOG_MAKEPRI */

#ifdef NEED_LOG_FAC
# define LOG_FAC(fac) fac
#endif /* NEED_LOG_FAC */

/* callbacks for the logging subsystem */
typedef void pbc_open_log(char *ident, int option, int facility);
typedef void pbc_log_func(pool *p, int priority, const char *msg);
typedef void pbc_close_log();

/**
 * Initializes the logging system.
 * @param pool Apache memory pool
 * @param ident the identification of this process
 * @param o optional function to replace openlog()
 * @param l optional function to replace syslog()
 * @param c optional function to replace closelog()
 */
void pbc_log_init(pool *p, const char *ident,
                  pbc_open_log *o, pbc_log_func *l, pbc_close_log *c);

/**
 * Log activity messages
 * @param pool Apache memory pool
 * @param logging_level the importance level of the message
 * @param message the message format to be logged
 * @param ... stuff to be logged.
 */
void pbc_log_activity(pool *p, int logging_level, const char *message,...);

/**
 * Log activity messages, takes a va_list.
 * @param pool Apache memory pool
 * @param logging_level the importance level of the message
 * @param message the message to be logged
 * @param arg a va_list to be logged.
 */
void pbc_vlog_activity(pool *p, int logging_level, const char *format, va_list arg);

/**
 * Create well-formed messages to be logged
 * @param pool Apache memory pool
 * @param info the string that contains the actual message
 * @param user the user's id
 * @param app_id the app_id of the requesting application
 * @return a nicely-formatted string to be logged
 */
char* pbc_create_log_message(pool *p, char *info, char *user, char *app_id);

/**
 * Closes the logging system.  Optional.
 */
void pbc_log_close();

#endif /* INCLUDED_PBC_LOGGING_H */
