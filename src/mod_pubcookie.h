/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is the pubcookie apache module header

 */

/*
    $Id: mod_pubcookie.h,v 2.1 2003-04-14 13:30:51 jteaton Exp $
 */
#ifndef INCLUDED_MOD_PUBCOOKIE_H
#define INCLUDED_MOD_PUBCOOKIE_H


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

/* apache includes */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"

/* ssleay lib stuff */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/des.h>
# include <openssl/rand.h>
# include <openssl/err.h>
#else
# include <pem.h>
# include <des.h>
# include <rand.h>
# include <err.h>
#endif /* OPENSSL_IN_DIR */

/* pubcookie stuff */
#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"

/* system stuff */
#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

/* misc prototype */
char *make_session_cookie_name(pool *, char *, unsigned char *);

module pubcookie_module;

typedef struct {
  table * configlist;
  int                   dirdepth;
  int                   noblank;
  char			*login;
  unsigned char		*appsrvid;
  char			*authtype_names; /* raw arg string from conf */
} pubcookie_server_rec;

typedef struct {
  int           inact_exp;
  int           hard_exp;
  int           failed;
  int           has_granting;
  int           non_ssl_ok;
  unsigned char *appid;
  char          creds;
  char          *end_session;
  int           redir_reason_no;
  char          *stop_message;
  int           session_reauth;
  pbc_cookie_data *cookie_data;
  unsigned char *addl_requests;

    /* for flavor_getcred */
    char *cred_transfer;
    int cred_transfer_len;
} pubcookie_dir_rec;

#endif /* INCLUDED_MOD_PUBCOOKIE_H */
