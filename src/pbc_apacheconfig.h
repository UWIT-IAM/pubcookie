/*

    Copyright 1999-2002, University of Washington.  All rights reserved.
    see doc/LICENSE.txt for copyright information

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|

    All comments and suggestions to pubcookie@cac.washington.edu
    More information: http://www.pubcookie.org/
    Written by the Pubcookie Team

    this is the routines for the apache config file

    mod_pubcookie stashes the config options in the server rec,
    these functions get them out

 */

/*
    $Id: pbc_apacheconfig.h,v 2.1 2003-04-14 13:30:51 jteaton Exp $
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

extern int errno;

pubcookie_server_rec * globalsr;
#define CONFIGLISTGROWSIZE 30 /* 100 */

int libpbc_apacheconfig_init(pool *p, void *initarg, const char *ident);

const char *libpbc_apacheconfig_getstring(pool *p, const char *key,
    const char *def);
const char **libpbc_apacheconfig_getlist(pool *p, const char *key);
const int libpbc_apacheconfig_getint(pool *p, const char *key,
    const char *def);
const int libpbc_apacheconfig_getswitch(pool *p, const char *key,
    const char *def);
