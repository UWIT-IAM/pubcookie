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

    the basic flavor of logins.  expect a username and a password and
    checks against one of the defined verifiers (see 'struct verifier'
    and verify_*.c for possible verifiers).
    
    will pass l->realm to the verifier and append it to the username when
    'append_realm' is set

 */

/*
    $Id: flavor_basic.c,v 1.32 2003-03-24 21:28:14 jjminer Exp $
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

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#include "snprintf.h"
#include "flavor.h"
#include "verify.h"
#include "security.h"

#include "pbc_config.h"
#include "pbc_logging.h"
#include "libpubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

static verifier *v = NULL;
extern int debug;

/* The types of reasons for printing the login page.. 
 * Should this be in a header?  I don't think I need it outside this file.. */

#define FLB_BAD_AUTH          1
#define FLB_REAUTH            2
#define FLB_LCOOKIE_ERROR     3
#define FLB_CACHE_CREDS_WRONG 4

/* The beginning size for the hidden fields */
#define INIT_HIDDEN_SIZE 2048
#define GETCRED_HIDDEN_MAX 512

static int init_basic()
{
    const char *vname;
    void *p;
    
    /* find the verifier configured */
    vname = libpbc_config_getstring(p, "basic_verifier", NULL);

    if (!vname) {
	pbc_log_activity(p, PBC_LOG_ERROR, 
			 "flavor_basic: no verifier configured");
	return -1;
    }

    v = get_verifier(vname);

    if (!v || !v->v) {
	pbc_log_activity(p, PBC_LOG_ERROR, 
			 "flavor_basic: verifier not found: %s", vname);
	v = NULL;
	return -1;
    }
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW,
		     "init_basic: using %s verifier", vname);
    return 0;
}

/*
 * return the length of the passed file in bytes or 0 if we cant tell
 * resets the file postion to the start
 */
static long file_size(pool *p, FILE *afile)
{
  long len;
  if (fseek(afile, 0, SEEK_END) != 0)
      return 0;
  len=ftell(afile);
  if (fseek(afile, 0, SEEK_SET) != 0)
      return 0;
  return len;
}

/* get the reason for our existing.  Returns NULL for an empty file. */

char * get_reason(pool *p, const char * reasonpage ) {
    char * reasonfile;
    const char * reasonpath = TMPL_FNAME;
    int reasonfilelen;
    int reason_len;
    FILE *reason_file;
    char * reasonhtml;
    int readlen;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "get_reason: hello");

    reasonfilelen = strlen(reasonpath) + strlen("/") + strlen(reasonpage) + 1;

    reasonfile = malloc( reasonfilelen * sizeof(char) );

    if ( snprintf( reasonfile, reasonfilelen, "%s%s%s",
                   reasonpath,
                   reasonpath[strlen(reasonpath) - 1 ] == '/' ? "" : "/",
                   reasonpage ) > reasonfilelen )  {
        /* Need to do something, we would have overflowed. */
        abend(p, "Reason filename overflow!\n");
    }

    reason_file = pbc_fopen(p, reasonfile, "r" );

    if (reason_file == NULL) {
        libpbc_abend(p, "Cannot open reasonfile %s", reasonfile );
    }

    reason_len = file_size(p, reason_file);

    if (reason_len == 0)
        return NULL;

    reasonhtml = malloc( (reason_len + 1) * sizeof( char ) );

    if ( reasonhtml == NULL ) {
        /* Out of memory! */
        libpbc_abend(p,  "Out of memory allocating to read reason file" );
    }

    readlen = fread( reasonhtml, 1, reason_len, reason_file );

    if (readlen != reason_len) {
        libpbc_abend(p,  "read %d when expecting %d on reason file read.",
                      readlen, reason_len );
    }

    reasonhtml[reason_len] = '\0';
    pbc_fclose(p, reason_file);
    free(reasonfile);

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "get_reason: goodbye");

    return reasonhtml;
}

static void print_login_page(pool *p, login_rec *l, login_rec *c, int reason)
{
    /* currently, we never clear the login cookie
       we always clear the greq cookie */
    int need_clear_login = 0;
    int need_clear_greq = 1;
    char message_out[1024];
    const char * reasonpage = NULL;

    char * hidden_fields = NULL;
    int hidden_len = 0;
    int hidden_needed_len = INIT_HIDDEN_SIZE;
    char * getcred_hidden = NULL;

    char * reason_html = NULL;
    
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "print_login_page: hello");

    /* set the cookies */
    if (need_clear_login) {
        print_header(p, "Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
                     PBC_L_COOKIENAME, 
                     PBC_CLEAR_COOKIE,
                     PBC_LOGIN_HOST,
                     LOGIN_DIR, 
                     EARLIEST_EVER);
    }

    if (need_clear_greq) {
        print_header(p, "Set-Cookie: %s=%s; domain=%s; path=/; secure\n",
                     PBC_G_REQ_COOKIENAME, 
                     PBC_CLEAR_COOKIE,
                     PBC_ENTRPRS_DOMAIN);

    }

    switch (reason) {
        case FLB_BAD_AUTH:
            reasonpage = libpbc_config_getstring(p,  "tmpl_login_bad_auth",
                                                  "login_bad_auth" );
            break;
        case FLB_REAUTH:
            reasonpage = libpbc_config_getstring(p,  "tmpl_login_reauth",
                                                  "login_reauth" );
            break;
        case FLB_CACHE_CREDS_WRONG:
            reasonpage = libpbc_config_getstring(p,  "tmpl_login_cache_creds_wrong",
                                                  "login_cache_creds_wrong" );
            break;
        case FLB_LCOOKIE_ERROR:
        default:
            reasonpage = libpbc_config_getstring(p,  "tmpl_login_nolcookie",
                                                  "login_nolcookie" );
            break;
    }

    if (reasonpage == NULL) {
        /* We shouldn't be here, but handle it anyway, of course. */
        libpbc_abend(p,  "Reasonpage is null, this is impossible." );
    }
    
    /* Get the HTML for the error reason */
    
    reason_html = get_reason(p, reasonpage);

    while (hidden_needed_len > hidden_len) {

        /* Just in case there's a bad implementation of realloc() .. */
        if (hidden_fields == NULL) {
            hidden_fields = malloc( hidden_needed_len * sizeof(char) );
        } else {
            hidden_fields = realloc( hidden_fields, hidden_needed_len * sizeof(char) );
        }

        if (hidden_fields == NULL) {
            /* Out of memory, ooops. */
            libpbc_abend(p,  "Out of memory allocating for hidden fields!" );
        }
        
        hidden_len = hidden_needed_len;

        /* Yeah, this sucks, but I don't know a better way. 
         * That doesn't mean there isn't one. */

        hidden_needed_len = snprintf( hidden_fields, hidden_len,
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%c\">\n" 
                                      "<input type=\"hidden\" name=\"%s\" value=\"%c\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
                                      PBC_GETVAR_APPSRVID, (l->appsrvid ? l->appsrvid : ""),
                                      PBC_GETVAR_APPID, (l->appid ? l->appid : ""),
                                      "creds_from_greq", l->creds_from_greq,
                                      PBC_GETVAR_CREDS, l->creds,
                                      PBC_GETVAR_VERSION, (l->version ? l->version : ""),
                                      PBC_GETVAR_METHOD, (l->method ? l->method : ""),
                                      PBC_GETVAR_HOST, (l->host ? l->host : ""),
                                      PBC_GETVAR_URI, (l->uri ? l->uri : ""),
                                      PBC_GETVAR_ARGS, (l->args ? l->args : ""),
                                      PBC_GETVAR_FR, (l->fr ? l->fr : ""),
                                      PBC_GETVAR_REAL_HOST, (l->real_hostname?l->real_hostname:""),
                                      PBC_GETVAR_APPSRV_ERR, (l->appsrv_err ? l->appsrv_err : ""),
                                      PBC_GETVAR_FILE_UPLD, (l->file ? l->file : ""),
                                      PBC_GETVAR_FLAG, (l->flag ? l->flag : ""),
                                      PBC_GETVAR_REFERER, (l->referer ? l->referer : ""),
                                      PBC_GETVAR_POST_STUFF, (l->post_stuff ? l->post_stuff : ""),
                                      PBC_GETVAR_SESSION_REAUTH, l->session_reauth,
                                      PBC_GETVAR_PRE_SESS_TOK, l->pre_sess_tok,
                                      "first_kiss", (l->first_kiss ? l->first_kiss : ""),
                                      PBC_GETVAR_REPLY, FORM_REPLY
                                    );
    }

    /* xxx save add'l requests */
    {
        /* xxx sigh, i have to explicitly save this */
        char *target = get_string_arg(p, PBC_GETVAR_CRED_TARGET,
                                      NO_NEWLINES_FUNC);

        if (target) {
            int needed_len;

            getcred_hidden = malloc( GETCRED_HIDDEN_MAX * sizeof(char) );

            if (getcred_hidden == NULL) {
                /* Out of memory */
                libpbc_abend(p,  "Out of memory allocating for GetCred" );
            }

            needed_len = snprintf( getcred_hidden, GETCRED_HIDDEN_MAX, 
                                   "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
                                   PBC_GETVAR_CRED_TARGET, target );

            if ( needed_len > GETCRED_HIDDEN_MAX ) {
                /* We were going to overflow, oops. */
                libpbc_abend(p,  "Almost overflowed writing GetCred" );
            }
        } 
    }

    /* Display the login form. */

    tmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_login",
                                            "login"),
                    PBC_LOGIN_URI,
                    reason_html != NULL ? reason_html : "",
                    hidden_fields,
                    getcred_hidden != NULL ? getcred_hidden : ""
                   );

    /* this tags the incoming request as a form reply */

    print_html(p, "\n");

    if (reason_html != NULL)
        free( reason_html );

    if (hidden_fields != NULL)
        free( hidden_fields );

    if (getcred_hidden != NULL)
        free( getcred_hidden );

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "print_login_page: goodbye");
}

/* process_basic():
   this routine is responsible for authenticating the user.
   if authentication is not possible (either the user hasn't logged in
   or the password was incorrect) it displays the login page and returns
   LOGIN_INPROGRESS.

   if authentication for this user will never succeed, it returns LOGIN_ERR.

   if authentication has succeeded, no output is generated and it returns
   LOGIN_OK.
 */
static login_result process_basic(pool *p, login_rec *l, login_rec *c,
				  const char **errstr)
{
    struct credentials *creds = NULL;
    struct credentials **credsp = NULL;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "process_basic: hello\n" );

    /* make sure we're initialized */
    assert(v != NULL);
    assert(l != NULL);
    /* c seems to always be null here. */
    /* XXX need to re-examine exactly what l and c should contain here */
    /* assert(c != NULL); */
    assert(errstr);

    *errstr = NULL;

    if (!v) {
        pbc_log_activity(p, PBC_LOG_ERROR,
                         "flavor_basic: flavor not correctly configured");
        return LOGIN_ERR;
    }

    /* choices, choices */

    /* index.cgi is responsible for extracting replies to the prompts
       that I printed into 'l'.  I'm responsible for modifying 'l' for
       later free rides.

       so, some possibilities:
       . reply from login page
       'l' is unauthed but has a username/pass that i should
       verify.  if yes, modify login cookie accordingly and return
       LOGIN_OK.  if no, print out the page and return
       LOGIN_INPROGRESS.

       . expired login cookie
       i should print out the page and return LOGIN_INPROGRESS.

       . valid login cookie
       i should return LOGIN_OK.
     */

    if (l->reply == FORM_REPLY) {
        if (libpbc_config_getswitch(p, "save_credentials", 0)) {
            credsp = &creds;
        }

        if (v->v(p, l->user, l->pass, NULL, l->realm, credsp, errstr) == 0) {
            if (debug) {
                /* xxx log realm */
                pbc_log_activity(p,  PBC_LOG_AUDIT,
                                  "authentication successful for %s\n", l->user );
            }

            /* authn succeeded! */

            /* xxx modify 'l' accordingly ? */

            /* optionally stick @REALM into the username */
            if (l->user && l->realm &&
                libpbc_config_getswitch(p, "append_realm", 0)) {
                /* append @REALM onto the username */
                char * tmp;
                tmp = pbc_malloc(p, strlen(l->user)+strlen(l->realm)+1);
                memset(tmp, 0, strlen(l->user)+strlen(l->realm)+1);
                if (tmp) {
                    strncat(tmp, l->user, strlen(l->user));
                    strncat(tmp, "@", 1);
                    strncat(tmp, l->realm, strlen(l->realm));
                    free (l->user);
                    l->user = tmp;
                }
            }

            /* if we got some long-term credentials, save 'em for later */
            if (creds != NULL) {
                char *outbuf;
                int outlen;
                char *out64;

                if (!libpbc_mk_priv(p, NULL, creds->str, creds->sz,
                                    &outbuf, &outlen)) {
                    /* save for later */
                    out64 = malloc(outlen * 4 / 3 + 20);
                    libpbc_base64_encode(p, (unsigned char *) outbuf,
                                          (unsigned char *) out64,
                                          outlen );

                    print_header(p, "Set-Cookie: %s=%s; domain=%s; secure\n",
                                 PBC_CRED_COOKIENAME, out64, PBC_LOGIN_HOST);

                    /* free buffer */
                    free(outbuf);
                    free(out64);
                } else {
                    pbc_log_activity(p, PBC_LOG_ERROR, 
                                     "libpbc_mk_priv failed: can't save credentials");
                }

                /* xxx save creds for later just in case we're
                   really flavor_getcred. this leaks. */
                l->flavor_extension = creds;

                creds = NULL;
            }

            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                             "process_basic: good login, goodbye\n" );

            return LOGIN_OK;
        } else {
            /* authn failed! */
            if (!*errstr) {
                *errstr = "authentication failed";
            }
            pbc_log_activity(p, PBC_LOG_AUDIT,
                             "flavor_basic: login failed for %s: %s", 
                             l->user == NULL ? "(null)" : l->user,
                             *errstr);

            /* make sure 'l' reflects that */
            l->user = NULL;	/* in case wrong username */
            print_login_page(p, l, c, FLB_BAD_AUTH);

            pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                             "process_basic: login in progress, goodbye\n" );
            return LOGIN_INPROGRESS;
        }
    } else if (l->session_reauth) {
        *errstr = "reauthentication required";
        pbc_log_activity(p, PBC_LOG_AUDIT, "flavor_basic: %s: %s", l->user, *errstr);

        print_login_page(p, l, c, FLB_REAUTH);
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                         "process_basic: login in progress, goodbye\n" );
        return LOGIN_INPROGRESS;

        /* l->check_error will be set whenever we couldn't decode the
           login cookie, including (for example) when the login cookie
           has expired. */
    } else if (l->check_error) {
        *errstr = l->check_error;
        pbc_log_activity(p, PBC_LOG_ERROR, "flavor_basic: %s", *errstr);

        print_login_page(p, l, c, FLB_LCOOKIE_ERROR);
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                         "process_basic: login in progress, goodbye\n" );
        return LOGIN_INPROGRESS;

        /* if l->check_error is NULL, then 'c' must be set and must
           contain the login cookie information */
    } else if (!c) {
        pbc_log_activity(p, PBC_LOG_ERROR,
                         "flavor_basic: check_error/c invariant violated");
        abort();

        /* make sure the login cookie represents credentials for this flavor */
    } else if (c->creds != PBC_BASIC_CRED_ID) {
        *errstr = "cached credentials wrong flavor";
        pbc_log_activity(p, PBC_LOG_ERROR, "flavor_basic: %s", *errstr);

        print_login_page(p, l, c, FLB_CACHE_CREDS_WRONG);
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                         "process_basic: login in progress, goodbye\n" );
        return LOGIN_INPROGRESS;

    } else { /* valid login cookie */
        pbc_log_activity(p, PBC_LOG_AUDIT,
                         "flavor_basic: free ride user: %s", l->user);
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                         "process_basic: free ride, goodbye\n" );
        return LOGIN_OK;
    }
}

struct login_flavor login_flavor_basic =
{
    "basic", /* name */
    PBC_BASIC_CRED_ID, /* id; see libpbc_get_credential_id() */
    &init_basic, /* init_flavor() */
    &process_basic /* process_request() */
};
