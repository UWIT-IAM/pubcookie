/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_apacheconfig.c
 * Apacheconfig
 *
 * $Id: pbc_apacheconfig.c,v 2.7 2003-07-03 04:25:21 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#if defined (APACHE1_3)
# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"
#else
typedef void pool;
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#ifdef HAVE_SYSEXITS_H
# include <sysexits.h>
#endif /* HAVE_SYSEXITS_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

#include "pbc_config.h"
#include "pbc_myconfig.h"
#include "snprintf.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "mod_pubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

pubcookie_server_rec * globalsr;

int libpbc_apacheconfig_init(pool *p, void *initarg, const char *ident)
{
    /*
     * stash a pointer to the server rec structure so the get functions
     * can access it
     */
    globalsr = (pubcookie_server_rec *) initarg;

    /* Look up umask */
    /* 
    val = libpbc_myconfig_getstring(p, "umask", "022");
    while (*val) {
        if (*val >= '0' && *val <= '7') umaskval = umaskval*8 + *val - '0';
        val++;
    }
    umask(umaskval);
     */

    /* paranoia checks */

    /* check that our login host is in our enterprise domain */
    /* if (!strstr(PBC_LOGIN_HOST, PBC_ENTRPRS_DOMAIN)) { */

    /* } */

    /* xxx check that our login URI points to our login host */

    /* xxx check that keydir exists */

    /* xxx check that we can read our symmetric key */

    /* xxx check that the granting certificate (public key) is readable */

    return 0;
}

const char *libpbc_apacheconfig_getstring(pool *p, const char *key, const char *def)
{
    table * configlist = globalsr->configlist;
    const char * ret;

    if ( key == NULL )
        return def;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, NULL, "looking for %s", key);

    ret = ap_table_get(configlist, key);
  
    if (ret) { 
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, NULL, "found %s with value %s", ret);
        return ret;
    } 
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, NULL, "failed to find %s, returning default %s", key, def);
    return def;
}

int libpbc_apacheconfig_getint(pool *p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring(p, key, (char *)0);
    
    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
        return def;
    return atoi(val);
}


/*
 * the rest of the functions need to be re-implemented in the apache scheme
 * i didn't bother because they're not used (yet)
 *
 */
char **libpbc_apacheconfig_getlist(pool *p, const char *key) {
   ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, NULL,
       "libpbc_apacheconfig_getlist not implmented, was looking for %s",
       key);
   return NULL;
} 

int libpbc_apacheconfig_getswitch(pool *p, const char *key, int def) {
   ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, NULL,
       "libpbc_apacheconfig_getswitch not implmented, was looking for %s",
       key);
   return def;
} 

/* these are the myconfig equivalents, for reference */
#if 0
char **libpbc_myconfig_getlist(pool *p, const char *key)
{
    const char *tval = libpbc_myconfig_getstring(p, key, NULL);
    char *val;
    char **ret;
    char *ptr;
    int c;

    if (tval == NULL) {
	return NULL;
    }

    c = 1; /* initial string */
    for (ptr = strchr(tval, ' '); ptr != NULL; ptr = strchr(ptr + 1, ' ')) {
	c++;
    }

    /* we malloc a buffer long enough for the subpointers followed by
       the string that we modify by adding \0 */
    ret = pbc_malloc(p, sizeof(char *) * (c + 2) + strlen(tval) + 1);
    if (!ret) {
	fatal(p, "out of memory", EX_OSERR);
    }

    /* copy the string to the end of the buffer.
       assumes sizeof(char) = 1 */
    val = ((char *) ret) + (sizeof(char *) * (c + 2));

    strcpy(val, tval);
    c = 0;
    ret[c++] = val;
    for (ptr = strchr(val, ' '); ptr != NULL; ptr = strchr(ptr, ' ')) {
	*ptr++ = '\0';
	if (*ptr == ' ') continue;
	ret[c++] = ptr;
    }
    ret[c] = NULL;

    return ret;
}

int libpbc_myconfig_getswitch(pool *p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring(p, key, (char *)0);

    if (!val) return def;
    
    if (*val == '0' || *val == 'n' ||
        (*val == 'o' && val[1] == 'f') || *val == 'f') {
        return 0;
    }
    else if (*val == '1' || *val == 'y' ||
             (*val == 'o' && val[1] == 'n') || *val == 't') {
        return 1;
    }

    return def;
}

#endif
