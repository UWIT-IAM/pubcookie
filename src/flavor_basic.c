/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file flavor_basic.c
 * The basic flavor of logins
 *
 *   expect a username and a password and
 *   checks against one of the defined verifiers (see 'struct verifier'
 *   and verify_*.c for possible verifiers).
 *   
 *   will pass l->realm to the verifier and append it to the username when
 *   'append_realm' is set
 *
 * $Id: flavor_basic.c,v 1.54 2004-04-08 21:09:06 fox Exp $
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
#include "pbc_configure.h"
#include "libpubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

static verifier *v = NULL;
extern int debug;

extern int get_kiosk_duration(pool *p, login_rec *l);

/* The types of reasons for printing the login page.. 
 * Should this be in a header?  I don't think I need it outside this file.. */

#define FLB_BAD_AUTH          1
#define FLB_REAUTH            2
#define FLB_LCOOKIE_ERROR     3
#define FLB_CACHE_CREDS_WRONG 4
#define FLB_PINIT             5
#define FLB_PLACE_HOLDER      6  /* for consistancy btwn flavors, why? */
#define FLB_LCOOKIE_EXPIRED   7
#define FLB_FORM_EXPIRED      8

/* The beginning size for the hidden fields */
#define INIT_HIDDEN_SIZE 2048
#define GETCRED_HIDDEN_MAX 512

static int init_basic()
{
    const char *vname;
    void *p = NULL;
    
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

/* get the html for user or password or whatever field, static or dynamic */
char *flb_get_field_html(pool *p, const char *field_page, const char *contents)
{
    char *field_html = NULL;   /* net result */
    char *fieldfile;
    const char *field_path = TMPL_FNAME;
    int filelen;
    int field_len;
    FILE *field_file;
    int readlen;
    char buf[PBC_1K];
    char *start = NULL;
    char *end = NULL;
    int len = ( contents != NULL ? strlen(contents) : 0 );
    char func[] = "flb_get_field_html";

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s: hello", func);

    filelen = strlen(field_path) + strlen("/") + strlen(field_page) + 1;

    fieldfile = malloc( filelen *sizeof(char) );

    if ( snprintf( fieldfile, filelen, "%s%s%s",
                   field_path,
                   field_path[strlen(field_path) - 1 ] == '/' ? "" : "/",
                   field_page ) > filelen )  {
        /* Need to do something, we would have overflowed. */
        abend(p, "field filename overflow!\n");
    }

    field_file = pbc_fopen(p, fieldfile, "r" );

    if (field_file == NULL) {
        libpbc_abend(p, "Cannot open field file %s", fieldfile );
    }

    field_len = file_size(p, field_file);

    if (field_len == 0)
        return NULL;

    if ( field_len >= sizeof(buf) ) {
        libpbc_abend(p,  "Need bigger buffer for reading form field file, %D not big enough", sizeof(buf) );
    }

    field_html = malloc( (field_len + 1) * sizeof( char ) + len );

    if ( field_html == NULL ) {
        /* Out of memory! */
        libpbc_abend(p,  "Out of memory allocating to field file" );
    }

    readlen = fread( buf, 1, field_len, field_file );

    if (readlen != field_len) {
        libpbc_abend(p,  "read %d when expecting %d on field file read.",
                      readlen, field_len );
    }

    pbc_fclose(p, field_file);
    if (fieldfile != NULL)
        free(fieldfile);

    buf[field_len] = '\0';
    strcpy(field_html, buf);

    /* if there is a substituion to be made, make it */
    while ( strstr(buf, "%contents%") != NULL ) {
        /* cheesy non-generic substitution for field */
        /* chop up the strings */
        end = strstr(strstr(buf, "%contents%")+1, "%");
        start = strstr(field_html, "%contents%");

        /* piece them back together */
        strcpy(start, (contents != NULL ? contents : ""));
        strcpy(start+len, end+1);

        strncpy(buf, field_html, PBC_1K);
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %s",
                func, field_html);

    return field_html;
}

/* figure out what html to use for user field */
char *flb_get_user_field(pool *p, login_rec *l, login_rec *c, int reason)
{
    char func[] = "flb_get_user_field";
    const char *loser = (l != NULL && l->user != NULL ? l->user
                        : (c != NULL ? c->user : NULL));
    const char *static_config = libpbc_config_getstring(p, "static_user_field",
                                STATIC_USER_FIELD_KIND);
    char *user_field_html;

    if ( strcmp(static_config, STATIC_USER_FIELD_KIND) == 0 ) {
        if ((c && c->user &&
               (reason==FLB_REAUTH || reason==FLB_CACHE_CREDS_WRONG)) ||
             (l->user && l->ride_free_creds == PBC_BASIC_CRED_ID) ) {
            user_field_html = flb_get_field_html(p, libpbc_config_getstring(p,
                                        "tmpl_login_user_static",
                                        "login_user_static" ), loser);
            l->hide_user = PBC_TRUE;
        }
        else {
            user_field_html = flb_get_field_html(p, libpbc_config_getstring(p,
                                        "tmpl_login_user_form_field",
                                        "login_user_form_field" ), loser);
            l->hide_user = PBC_FALSE;
        }
    }
    else if ( strcmp(static_config, STATIC_USER_FIELD_FASCIST) == 0 ) {
        if ( c != NULL && c->user != NULL ||
             l->user != NULL && l->ride_free_creds == PBC_BASIC_CRED_ID ) {
            user_field_html = flb_get_field_html(p, libpbc_config_getstring(p,
                                        "tmpl_login_user_static",
                                        "login_user_static" ), loser);
            l->hide_user = PBC_TRUE;
        }
        else {
            user_field_html = flb_get_field_html(p, libpbc_config_getstring(p,
                                        "tmpl_login_user_form_field",
                                        "login_user_form_field" ), loser);
            l->hide_user = PBC_FALSE;
        }
    }
    else { /* STATIC_USER_FIELD_NEVER */
        user_field_html = flb_get_field_html(p, libpbc_config_getstring(p,
                                        "tmpl_login_user_form_field",
                                        "login_user_form_field" ), loser);
        l->hide_user = PBC_FALSE;
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %s",
                func, user_field_html);
    return(user_field_html);

}

/* get the html for user field, static or dynamic */
char *flb_get_hidden_user_field(pool *p, login_rec *l, login_rec *c, int reason)
{
    const char *loser = (l != NULL && l->user != NULL ? l->user
                        : (c != NULL ? c->user : NULL));

    if ( l != NULL && l->hide_user == PBC_TRUE )
        return(flb_get_field_html(p, libpbc_config_getstring(p,
                                        "tmpl_login_user_hidden",
                                        "login_user_hidden" ), loser));
    else
        return(NULL);

}

static void print_login_page(pool *p, login_rec *l, login_rec *c, int reason)
{
    /* currently, we never clear the login cookie
       we always clear the greq cookie */
    int need_clear_login = 0;
    int need_clear_greq = 1;
    const char * reasonpage = NULL;

    char *hidden_fields = NULL;
    int hidden_len = 0;
    int hidden_needed_len = INIT_HIDDEN_SIZE;
    char *getcred_hidden = NULL;

    char *reason_html = NULL;
    char *user_field = NULL;
    char *hidden_user = NULL;
    char now[64];
    int ldur, ldurp;
    char ldurtxt[64], *ldurtyp;
    
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "print_login_page: hello reason: %d", reason);

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
            /* username will be static and prefilled use a different bad
               auth message, one without comments about the username */
            /* left the default file the same only config key is different */
            if( c != NULL && c->user != NULL )
                reasonpage = libpbc_config_getstring(p,  "tmpl_login_bad_auth_static_user",
                                                  "login_bad_auth" );
            else
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
        case FLB_PINIT:
            reasonpage = libpbc_config_getstring(p,  "tmpl_login_pinit",
                                                  "login_pinit" );
            break;
        case FLB_LCOOKIE_EXPIRED:
            reasonpage = libpbc_config_getstring(p, "tmpl_login_expired",
                                                  "login_expired" );
            break;
        case FLB_FORM_EXPIRED:
            reasonpage = libpbc_config_getstring(p, "tmpl_form_expired",
                                                  "form_expired" );
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
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%ld\">\n",
                                      PBC_GETVAR_APPSRVID, (l->appsrvid ? l->appsrvid : ""),
                                      PBC_GETVAR_APPID, (l->appid ? l->appid : ""),
                                      "creds_from_greq", l->creds_from_greq,
                                      PBC_GETVAR_CREDS, l->creds,
                                      PBC_GETVAR_VERSION, (l->version ? l->version : ""),
                                      PBC_GETVAR_METHOD, (l->method ? l->method : ""),
                                      PBC_GETVAR_HOST, (l->host ? l->host : ""),
                                      PBC_GETVAR_URI, (l->uri ? l->uri : ""),
                                      PBC_GETVAR_RELAY_URL, (l->relay_uri ? l->relay_uri : ""),
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
                                      PBC_GETVAR_PINIT, l->pinit,
                                      PBC_GETVAR_REPLY, FORM_REPLY,
                                      PBC_GETVAR_CREATE_TS, time(NULL)
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

    snprintf(now, sizeof(now), "%ld", time(NULL));

    /* what should the user field look like? */
    user_field = flb_get_user_field(p, l, c, reason);

    /* if the user field should be hidden */
    hidden_user = flb_get_hidden_user_field(p, l, c, reason);

    /* login session lifetime message */
    if (!(ldur=get_kiosk_duration(p,l)))
       ldur = libpbc_config_getint(p, "default_l_expire",DEFAULT_LOGIN_EXPIRE);
    if (((ldurp=ldur/3600)*3600) == ldur) ldurtyp = "hour";
    else if (((ldurp=ldur/60)*60) == ldur) ldurtyp = "minute";
    else ldurp = ldur, ldurtyp = "second";
    sprintf(ldurtxt, "%d %s%s", ldurp, ldurtyp, ldurp==1?"":"s");

    /* Display the login form. */
    ntmpl_print_html(p, TMPL_FNAME,
                     libpbc_config_getstring(p, "tmpl_login", "login"),
                    "loginuri", PBC_LOGIN_URI,
                    "message", reason_html != NULL ? reason_html : "",
                    "curtime", now, 
                    "hiddenuser", hidden_user != NULL ? hidden_user : "",
                    "hiddenfields", hidden_fields,
                    "user_field", user_field != NULL ? user_field : "",
                    "getcredhidden", getcred_hidden != NULL ? getcred_hidden : "",
                    "durationtext", ldurtxt,
                    NULL
                   );

    /* this tags the incoming request as a form reply */

    print_html(p, "\n");

    if (user_field != NULL)
        free( user_field );

    if (reason_html != NULL)
        free( reason_html );

    if (hidden_user != NULL)
        free( hidden_user );

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
static login_result process_basic(pool *p, const security_context *context,
                                  login_rec *l, login_rec *c,
				  const char **errstr)
{
    struct credentials *creds = NULL;
    struct credentials **credsp = NULL;
    int also_allow_cred = 0;
    int rcode;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "process_basic: hello\n" );
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
         "process_basic: create=%d,  reauth=%d\n",
         c?c->create_ts:(-1), l->session_reauth );

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

    /* allow flavor basic to honor login cookies from other flavors */
    also_allow_cred = libpbc_config_getint(p, "basic_also_accepts", 0) + 48;

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

        /* Make sure response is timely */
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
               "process_basic: create=%d\n", l->create_ts);
        if (l->create_ts && (time(NULL) > (l->create_ts+30))) {
            *errstr = "You have 30 seconds to login";
            rcode = FLB_FORM_EXPIRED;
        } else if (v->v(p, l->user, l->pass, NULL,
                     l->realm, credsp, errstr) == 0) {
            if (debug) {
                /* xxx log realm */
                pbc_log_activity(p,  PBC_LOG_AUDIT,
                    	"Authentication success: %s IP: %s type: %c\n", 
			l->user,
                        (cgiRemoteAddr == NULL ? "(null)" : cgiRemoteAddr),
			l->creds);
            }

            /* authn succeeded! */

            /* set the create time */
            l->create_ts = time(NULL);
            if( c != NULL )
                c->create_ts = time(NULL);

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

                if (!libpbc_mk_priv(p, context, NULL, 0, creds->str, creds->sz,
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

            if ( ! libpbc_config_getswitch(p, "retain_username_on_failed_authn", 0)) {
                l->user = NULL;	/* in case wrong username */
            }
            rcode = FLB_BAD_AUTH;
        }

    /* Auth request entry. */
    /* If reauth, check time limit */
    } else if (l->session_reauth &&  
           ( (l->session_reauth==1) ||
             (c && (c->create_ts+(l->session_reauth) < time(NULL))) )) {
        *errstr = "reauthentication required";
        rcode = FLB_REAUTH;

    /* If the pinit flag is set, show a pinit login page */
    } else if (l->pinit == PBC_TRUE) {
        *errstr = "pinit";
        rcode = FLB_PINIT;

    /* l->check_error will be set whenever the l cookie isn't valid
       including (for example) when the login cookie has expired.  */
    } else if (l->check_error) {
        *errstr = l->check_error;
        if (strcmp(l->check_error,"expired")) rcode = FLB_LCOOKIE_ERROR;
        else rcode = FLB_LCOOKIE_EXPIRED;

    /* if l->check_error is NULL, then 'c' must be set and must
       contain the login cookie information */
    } else if (!c) {
        pbc_log_activity(p, PBC_LOG_ERROR,
                         "flavor_basic: check_error/c invariant violated");
        abort();

    /* make sure the login cookie represents credentials for this flavor */
    } else if (c->creds != PBC_BASIC_CRED_ID && c->creds != also_allow_cred) {
        *errstr = "cached credentials wrong flavor";
        rcode = FLB_CACHE_CREDS_WRONG;

    } else { /* valid login cookie */
        pbc_log_activity(p, PBC_LOG_AUDIT,
                         "flavor_basic: L cookie valid user: %s", l->user);
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                         "process_basic: L cookie valid, goodbye\n" );
        return LOGIN_OK;
    }

    /* User not properly logged in.  Show login page unless quiet login */ 
    pbc_log_activity(p, PBC_LOG_ERROR,
            "flavor_basic: %s: %s", l->user?l->user:"(null)", *errstr);
    if (l->flag && strchr(l->flag, 'Q')) {
       pbc_log_activity(p, PBC_LOG_ERROR,
            "flavor_basic: quiet login, returning no user");
       l->user = strdup("");
       return LOGIN_OK;
    }
       
    print_login_page(p, l, c, rcode);
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
                     "process_basic: login in progress, goodbye\n" );
    return LOGIN_INPROGRESS;
}

struct login_flavor login_flavor_basic =
{
    "basic", /* name */
    PBC_BASIC_CRED_ID, /* id; see libpbc_get_credential_id() */
    &init_basic, /* init_flavor() */
    &process_basic /* process_request() */
};
