/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: pbc_apacheconfig.h,v 2.5 2003-07-02 23:27:05 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"

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
#define CONFIGLISTGROWSIZE 30 /* 100 */

int libpbc_apacheconfig_init(apr_pool_t *p, void *initarg, const char *ident);

const char *libpbc_apacheconfig_getstring(apr_pool_t *p, const char *key,
    const char *def);
char **libpbc_apacheconfig_getlist(apr_pool_t *p, const char *key);
int libpbc_apacheconfig_getint(apr_pool_t *p, const char *key, int def);
int libpbc_apacheconfig_getswitch(apr_pool_t *p, const char *key, int def);
