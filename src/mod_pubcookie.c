/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file mod_pubcookie.c
 * Apache pubcookie module
 *
 * $Id: mod_pubcookie.c,v 1.128 2004-02-16 17:05:31 jteaton Exp $
 */


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
#include "pbc_myconfig.h"
#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"
#include "mod_pubcookie.h"
#include "pbc_apacheconfig.h"
#include "pbc_configure.h"

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

void dump_server_rec(request_rec *r, pubcookie_server_rec *scfg) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
               "dump_server_rec:\n\
		dirdepth: %d\n\
		noblank: %d\n\
		login: %s\n\
		appsrvid: %s\n\
		authtype_names: %s", 
		scfg->dirdepth, 
		scfg->noblank, 
  		(scfg->login == NULL ? "" : scfg->login),
  		(scfg->appsrvid == NULL ? "" : (char *)scfg->appsrvid),
  		(scfg->authtype_names == NULL ? "" : (char *)scfg->authtype_names));

}

void dump_dir_rec(request_rec *r, pubcookie_dir_rec *cfg) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
               "dump_dir_rec:\n\
		inact_exp: %d\n\
                hard_exp: %d\n\
                failed: %d\n\
                has_granting: %d\n\
                non_ssl_ok: %d\n\
		appid: %s\n\
                creds: %c\n\
                end_session: %s\n\
                redir_reason_no: %d\n\
                stop_message: %s\n\
                session_reauth: %d",
  		cfg->inact_exp,
  		cfg->hard_exp,
  		cfg->failed,
  		cfg->has_granting,
  		cfg->non_ssl_ok,
  		(cfg->appid == NULL ? "" : (char *)cfg->appid),
  		cfg->creds,
  		(cfg->end_session == NULL ? "" : (char *)cfg->end_session),
  		cfg->redir_reason_no,
  		(cfg->stop_message == NULL ? "" : (char *)cfg->stop_message),
  		cfg->session_reauth);

}

/**
 * read the post stuff and spit it back out
 * @param r reuquest_rec
 * @return int 
 */
int put_out_post(request_rec *r) {
   char argsbuffer[HUGE_STRING_LEN];
   int retval;

   /* checkout http_protocols.c for reading the body info */
   if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
        return retval;

   if (ap_should_client_block(r)) {
        int len_read;

        ap_hard_timeout("copy script args", r);

        while ((len_read =
                ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN)) > 0) {
            ap_reset_timeout(r);
            if (ap_rwrite(argsbuffer, len_read, r) < len_read) {
                /* something went wrong writing, chew up the rest */
                while(ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0) {
                    /* dump it */
                }
                break;
            }
        }

        ap_kill_timeout(r);
    }
    return(1);

}

/**
 * get a random int used to bind the granting cookie and pre-session
 * @returns random int or -1 for error
 * but, what do we do about that error?
 */
int get_pre_s_token(request_rec *r) {
    int i;
    
    if( (i = libpbc_random_int(r->pool)) == -1 ) {
        ap_log_rerror(APLOG_MARK, APLOG_EMERG|APLOG_NOERRNO, r, 
		"get_pre_s_token: OpenSSL error");
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r, 
		"get_pre_s_token: token is %d", i);
    return(i);

}

/*                                                                            */
unsigned char *get_app_path(request_rec *r, const char *path) {
    char *path_out;
    int truncate;
    pool *p = r->pool;
    pubcookie_server_rec *scfg;

    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                                       &pubcookie_module);

    if( scfg->dirdepth ) {
        if( scfg->dirdepth < ap_count_dirs(path) )
            truncate = scfg->dirdepth;
        else
            truncate = ap_count_dirs(path);
        path_out = ap_make_dirstr(p, path, truncate);
    }
    else {
        path_out = ap_make_dirstr(p, path, ap_count_dirs(path));
    }

    return (unsigned char *) path_out;

}

int check_end_session(request_rec *r) {
    int 		  ret = 0;
    const char            *end_session;
    char                  *word;
    pool                  *p = r->pool;
    pubcookie_dir_rec     *cfg;

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);

    end_session = cfg->end_session;

    /* check list of end session args */
    while( end_session != NULL && *end_session != '\0' &&
		 (word = ap_getword_white(p, &end_session)) ) {

        if( strcasecmp(word, PBC_END_SESSION_ARG_REDIR) == 0 ) {
            ret = ret | PBC_END_SESSION_REDIR;
        }
        if( strcasecmp(word, PBC_END_SESSION_ARG_CLEAR_L) == 0 ) {
            ret = ret | PBC_END_SESSION_CLEAR_L 
		      | PBC_END_SESSION_REDIR;
        }
        else if( strcasecmp(word, PBC_END_SESSION_ARG_ON) == 0 ) {
            ret = ret | PBC_END_SESSION_ONLY;
        }
        else if( strcasecmp(word, PBC_END_SESSION_ARG_OFF) == 0 ) {
            /* off means off, nothing else */
            return(PBC_END_SESSION_NOPE);
        }
    }

    return(ret);

}

/* converts an authtype name to a pubcookie credential number */
char pubcookie_auth_type(request_rec *r) {
    pubcookie_server_rec      *scfg;
    pubcookie_dir_rec 	      *cfg;
    pool                      *p = r->pool;
    const char                *auth_type;
    const char                *type_names;
    char                      *word;
    int                       i;
    
    scfg=(pubcookie_server_rec *)ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);
    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    type_names = scfg->authtype_names;
    auth_type = ap_auth_type(r);

    /* check list of pubcookie auth_types */
    /* xxx this only works if the credential id is '0', '1', ... */
    i = 1;
    while( type_names != NULL && *type_names != '\0' &&
		 (word = ap_getword_conf(p, &type_names)) ) {
        if( strcasecmp(word, auth_type) == 0 ) 
            return(i + '0');
        i++;
    }

    /* ok, check the list in libpubcookie */
    return libpbc_get_credential_id(p, auth_type);
}

request_rec *main_rrec (request_rec *r) {
    request_rec *mr = r;
    while (mr->main)
        mr = mr->main;
    return mr;
}

/* figure out the appid                                                      */
unsigned char *appid(request_rec *r)
{
    pubcookie_server_rec	*scfg;
    pubcookie_dir_rec		*cfg;
    request_rec 		*rmain = main_rrec (r);

    cfg=(pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);

    if( cfg->appid )
        return(cfg->appid);
    else
        return get_app_path(r, rmain->parsed_uri.path);

}

/* figure out the appsrvid                                                   */
unsigned char *appsrvid(request_rec *r)
{
    pubcookie_server_rec	*scfg;
    pubcookie_dir_rec		*cfg;

    cfg=(pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);

    if( scfg->appsrvid )
        return(scfg->appsrvid);
    else
        /* because of multiple passes through don't use r->hostname() */
        return (unsigned char *) ap_pstrdup(r->pool, ap_get_server_name(r));

}

/* make sure agents don't cache the redirect */
void set_no_cache_headers(request_rec *r) {

    ap_table_set(r->headers_out, "Expires", ap_gm_timestr_822(r->pool, 
		r->request_time));
    ap_table_set(r->headers_out, "Cache-Control", "no-cache");
    ap_table_set(r->headers_out, "Pragma", "no-cache");

}

/* set or reset the session cookie */
static void set_session_cookie(request_rec *r, int firsttime) 
{
    pubcookie_dir_rec    *cfg;
    pubcookie_server_rec *scfg;
    char                 *new_cookie;
    unsigned char        *cookie;
#ifdef PORT80_TEST
    char *secure = "";
#else
    char *secure = " secure";
#endif

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                                     &pubcookie_module);
    scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                                         &pubcookie_module);
    
    if( firsttime != 1 ) {
        /* just update the idle timer */
        /* xxx it would be nice if the idle timeout has been disabled
           to avoid recomputing and resigning the cookie? */
        cookie = libpbc_update_lastts(r->pool, scfg->sectext, cfg->cookie_data, NULL, 0);
    } else {
        /* create a brand new cookie, initialized with the present time */
        cookie = libpbc_get_cookie(r->pool, 
                                     scfg->sectext,
				     (unsigned char *)r->connection->user, 
                                     PBC_COOKIE_TYPE_S, 
				     cfg->creds, 
				     23, 
				     (unsigned char *)appsrvid(r), 
				     appid(r), 
				     NULL,
					 0);
    }

    new_cookie = ap_psprintf(r->pool, "%s=%s; path=%s;%s", 
			     make_session_cookie_name(r->pool, 
                             PBC_S_COOKIENAME, 
                             appid(r)),
			     cookie, 
			     "/",
                             secure);

    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);

    if (firsttime && cfg->cred_transfer) {
        char *blob = NULL;
        int bloblen;
        char *base64 = NULL;
        int res = 0;

	/* save the transfer creds in a cookie; we only need to do this
         the first time since our cred cookie doesn't expire (which is poor
         and why we need cookie extensions) */
        /* encrypt */
        if (libpbc_mk_priv(r->pool, scfg->sectext, NULL, 0, cfg->cred_transfer,
                           cfg->cred_transfer_len,
                           &blob, &bloblen)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "credtrans: libpbc_mk_priv() failed");
            res = -1;
        }

        /* base 64 */
        if (!res) {
            base64 = ap_palloc(r->pool, (bloblen + 3) / 3 * 4 + 1);
            if (!libpbc_base64_encode(r->pool, (unsigned char *) blob, 
                                       (unsigned char *) base64, bloblen)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, r, 
                              "credtrans: libpbc_base64_encode() failed");
                res = -1;
            }
        }

        /* set */
        new_cookie = ap_psprintf(r->pool, "%s=%s; path=%s;%s", 
                                 make_session_cookie_name(r->pool, 
                                                          PBC_CRED_COOKIENAME,
                                                          appid(r)),
                                 base64,
                                 "/",
                                 secure);
        ap_table_add(r->headers_out, "Set-Cookie", new_cookie);

	/* xxx eventually when these are just cookie extensions, they'll
	 automatically be copied from the granting cookie to the 
	 session cookies and from session cookie to session cookie */
    }
}

/** clear granting cookie */
void clear_granting_cookie(request_rec *r) {
    char   *new_cookie;
#ifdef PORT80_TEST
    char *secure = "";
#else
    char *secure = " secure";
#endif
    pool *p = r->pool;

    new_cookie = ap_psprintf(r->pool, 
                 "%s=; domain=%s; path=/; expires=%s;%s", 
       PBC_G_COOKIENAME, 
       PBC_ENTRPRS_DOMAIN,
       EARLIEST_EVER, secure);

    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
}

/* clear cred transfer cookie */
void clear_transfer_cookie(request_rec *r) {
    char   *new_cookie;
#ifdef PORT80_TEST
    char *secure = "";
#else
    char *secure = " secure";
#endif
    pool *p = r->pool;

    new_cookie = ap_psprintf(r->pool, 
                             "%s=; domain=%s; path=/; expires=%s;%s", 
                             PBC_CRED_TRANSFER_COOKIENAME,
                             PBC_ENTRPRS_DOMAIN,
                             EARLIEST_EVER, secure);
    
    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
}

/** clear pre session cookie */
void clear_pre_session_cookie(request_rec *r) {
    char   *new_cookie;
#ifdef PORT80_TEST
    char *secure = "";
#else
    char *secure = " secure";
#endif

    new_cookie = ap_psprintf(r->pool, 
                 "%s=; path=/; expires=%s;%s", 
       PBC_PRE_S_COOKIENAME, 
       EARLIEST_EVER, secure);

    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);

}

void clear_session_cookie(request_rec *r) {
    char   *new_cookie;
    pubcookie_dir_rec    *cfg;
#ifdef PORT80_TEST
    char *secure = "";
#else
    char *secure = " secure";
#endif

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                                     &pubcookie_module);

    new_cookie = ap_psprintf(r->pool, 
		"%s=%s; path=/; expires=%s;%s",
                make_session_cookie_name(r->pool, PBC_S_COOKIENAME, appid(r)), 
	        PBC_CLEAR_COOKIE,
                EARLIEST_EVER,
                secure);
                             
    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);

    if (cfg->cred_transfer) {
        /* extra cookies (need cookie extensions) */
        new_cookie = ap_psprintf(r->pool, 
                                 "%s=%s; path=/; expires=%s;%s",
                                 make_session_cookie_name(r->pool, 
                                                          PBC_CRED_COOKIENAME, 
                                                          appid(r)), 
                                 PBC_CLEAR_COOKIE,
                                 EARLIEST_EVER,
                                 secure);
        
        ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
    }
}

/**
 * handler to process end session redirects
 * @param r the apache request rec
 * @return OK to let Apache know to finish the request
 */
static int do_end_session_redirect_handler(request_rec *r) {
    pubcookie_dir_rec    *cfg;
    pubcookie_server_rec *scfg;
    char                 *refresh;

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config, 					 &pubcookie_module);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
        "do_end_session_redirect_handler: hello");
      
    r->content_type = "text/html";
    clear_granting_cookie(r);
    clear_pre_session_cookie(r);
    clear_session_cookie(r);
    set_no_cache_headers(r);

    ap_send_http_header(r);

    refresh = ap_psprintf(r->pool, "%d;URL=%s?%s=%d&%s=%s&%s=%s", 
		PBC_REFRESH_TIME, 
		scfg->login,
		PBC_GETVAR_LOGOUT_ACTION,
                (check_end_session(r) & PBC_END_SESSION_CLEAR_L ?
			LOGOUT_ACTION_CLEAR_L : LOGOUT_ACTION_NOTHING),
		PBC_GETVAR_APPID,
		appid(r),
		PBC_GETVAR_APPSRVID,
		appsrvid(r));

    ap_rprintf(r, "<HTML>\n");
    ap_rprintf(r, " <HEAD>\n");
    ap_rprintf(r, "  <meta HTTP-EQUIV=\"Refresh\" CONTENT=\"%s\">\n", refresh);
    ap_rprintf(r, " </HEAD>\n");
    ap_rprintf(r, " <BODY BGCOLOR=\"#FFFFFF\">\n");
    ap_rprintf(r, " </BODY>\n");
    ap_rprintf(r, "</HTML>\n");

    return(OK);
}

/**
 * give an error message and stop the transaction, i.e. don't loop
 * @param r reuquest_rec
 * @return OK
 * this is kinda bogus since it looks like a successful request but isn't
 * but it's far less bogus than looping between the WLS and AS forever ...
 */
static int stop_the_show_handler(request_rec *r)
{
    pubcookie_dir_rec    *cfg;
    pubcookie_server_rec *scfg;
    char                 *refresh;

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config, 					 &pubcookie_module);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
        "stop_the_show_handler: hello");
      
    r->content_type = "text/html";
    clear_granting_cookie(r);
    clear_pre_session_cookie(r);
    clear_session_cookie(r);
    set_no_cache_headers(r);

    ap_send_http_header(r);

    ap_rprintf(r, "<HTML>\n");
    ap_rprintf(r, " <HEAD>\n");
    ap_rprintf(r, "  <TITLE>A problem has occurred</TITLE>\n");
    ap_rprintf(r, " </HEAD>\n");
    ap_rprintf(r, " <BODY BGCOLOR=\"#FFFFFF\">\n");
    ap_rprintf(r, "  <H1>A problem has occurred</H1>\n");
    ap_rprintf(r, "  <P>%s</P>\n", cfg->stop_message);
    ap_rprintf(r, "  <P>Hitting Refresh will attempt to ");
    ap_rprintf(r, "  resubmit your request</P>\n");
    ap_rprintf(r, " </BODY>\n");
    ap_rprintf(r, "</HTML>\n");

    return(OK);

}

request_rec *top_rrec (request_rec *r) {
    request_rec *mr = r;

    for (;;) {
        while (mr->main)
            mr = mr->main;
        while (mr->prev)
            mr = mr->prev;
        if (! mr->main)
            break;
    }
    return mr;
}

int blank_cookie(request_rec *r, char *name) {
    const char *cookie_header; 
    char *cookie;
    char *ptr;
    request_rec *mr = top_rrec (r);
    char *c2;
    char *name_w_eq;
    pubcookie_server_rec *scfg;
    scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config, &pubcookie_module);
  
    if (scfg->noblank) return(0);
  
    /* If we've stashed the cookie, we know it's already blanked */
    if(ap_table_get(mr->notes, name) ||
        !(cookie_header = ap_table_get(r->headers_in, "Cookie")))
      return 0;

    /* if we aint got an authtype they we definately aint pubcookie */
    /* then again, we want to always blank cookies */
    /* if(!ap_auth_type(r))                        */
    /*   return DECLINED;                          */

    /* add an equal on the end */
    name_w_eq = ap_pstrcat(r->pool, name, "=", NULL);

    if(!(cookie = strstr(cookie_header, name_w_eq)))
        return 0;

    cookie += strlen(name_w_eq);

    /*
     * Because the cookie blanking affects the whole subrequest chain, we
     * need to stash the cookie away to be used again later.  We need cookies
     * to persist among subrequests, either because subrequests need the
     * cookie, such as in mod_cern_meta, or because the first time fixups is
     * run and blanks the cookies is during a subrequest itself.
     *
     * Because of all this, we stash in the topmost request's notes table.
     * Note that we must use the topmost request's pool instead of our own
     * pool!
     */
    c2 = ap_pstrdup (mr->pool, cookie);
    if( (ptr = strchr (c2, ';')) )
        *ptr = '\0';
    ap_table_set (mr->notes, name, c2);

    ptr = cookie;
    while(*ptr) {
        if(*ptr == ';')
            break;
        *ptr = PBC_X_CHAR;
        ptr++;
    }

    ap_table_set(r->headers_in, "Cookie", cookie_header);

    return (int)ptr;

}

/* Herein we deal with the redirect of the request to the login server        */
/*    if it was only that simple ...                                          */
static int auth_failed_handler(request_rec *r) {
    pool                 *p = r->pool;
    char                 *tmp = ap_palloc(p, PBC_1K);
    char                 *refresh = ap_palloc(p, PBC_1K);
    char                 *pre_s = ap_palloc(p, PBC_1K);
    char                 *pre_s_cookie = ap_palloc(p, PBC_1K);
    char                 *g_req_cookie = ap_palloc(p, PBC_4K);
    char                 *g_req_contents = ap_palloc(p, PBC_4K);
    char                 *e_g_req_contents;
    const char *tenc = ap_table_get(r->headers_in, "Transfer-Encoding");
    const char *ctype = ap_table_get(r->headers_in, "Content-type");
    const char *lenp = ap_table_get(r->headers_in, "Content-Length");
    char                 *host = NULL;
    char                 *args;
    char                 *refresh_e;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec    *cfg;
    request_rec          *mr = top_rrec (r);
    char                 misc_flag = '0';
    char                 *file_to_upld = NULL;
    const char           *referer;
    int			 pre_sess_tok;
#ifdef PORT80_TEST
    char *secure = "";
#else
    char *secure = " secure";
#endif

    cfg=(pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
        "auth_failed_handler: hello");

    /* reset these dippy flags */
    cfg->failed = 0;

    /* deal with GET args */
    if ( r->args ) {
        args = ap_pcalloc (p, (strlen (r->args) + 3) / 3 * 4 + 1);
        libpbc_base64_encode(p, (unsigned char *) r->args, 
			      (unsigned char *) args, strlen(r->args));
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
            "GET args before encoding length %d, string: %s", 
            strlen(r->args), r->args);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
            "GET args after encoding length %d, string: %s", 
            strlen(args), args);
    }
    else
        args = ap_pstrdup(p, "");

    r->content_type = "text/html";

    /* if there is a non-standard port number just tack it onto the hostname  */
    /* the login server just passes it through and the redirect works         */
    if ( (r->server->port != 80) && ( r->server->port != 443 )) {
        /* because of multiple passes through don't use r->hostname() */
        host = ap_psprintf(p, "%s:%d", ap_get_server_name(r), r->server->port);
    }

    if ( ! host ) 
        /* because of multiple passes through on www don't use r->hostname() */
        host = ap_pstrdup(p, ap_get_server_name(r));

    /* To knit the referer history together */
    referer = ap_table_get(r->headers_in, "Referer");

    if( (pre_sess_tok=get_pre_s_token(r)) == -1 ) {
        /* this is weird since we're already in a handler */
        cfg->stop_message = ap_pstrdup(p, "Couldn't get pre session token");
        stop_the_show_handler(r);
        return(OK);
    }

    /* make the granting request */
    /* the granting request is a cookie that we set  */
    /* that gets sent up to the login server cgi, it */
    /* is our main way of communicating with it      */
    ap_snprintf(g_req_contents, PBC_4K-1, 
          "%s=%s&%s=%s&%s=%c&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%d&%s=%s&%s=%s&%s=%d&%s=%d&%s=%c", 
          PBC_GETVAR_APPSRVID,
          appsrvid(r),
          PBC_GETVAR_APPID, 
          appid(r),
          PBC_GETVAR_CREDS, 
          cfg->creds, 
          PBC_GETVAR_VERSION, 
          PBC_VERSION, 
          PBC_GETVAR_METHOD, 
          r->method, 
          PBC_GETVAR_HOST, 
          host,
          PBC_GETVAR_URI, 
          mr->uri,
          PBC_GETVAR_ARGS, 
          args,
          PBC_GETVAR_REAL_HOST,
          ap_get_local_host(p),
          PBC_GETVAR_APPSRV_ERR,
          cfg->redir_reason_no,
          PBC_GETVAR_FILE_UPLD,
          (file_to_upld ? file_to_upld : ""),
          PBC_GETVAR_REFERER,
          referer,
          PBC_GETVAR_SESSION_REAUTH,
          (cfg->session_reauth == PBC_UNSET_SESSION_REAUTH ?
			PBC_SESSION_REAUTH_NO : cfg->session_reauth),
	  PBC_GETVAR_PRE_SESS_TOK,
          pre_sess_tok,
          PBC_GETVAR_FLAG,
          misc_flag);

    if (cfg->addl_requests) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
	    "auth_failed_handler: adding %s", cfg->addl_requests);

	g_req_contents = ap_pstrcat(p, g_req_contents, 
				    cfg->addl_requests, NULL);
    }

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
        "g_req before encoding length %d, string: %s", 
        strlen(g_req_contents), g_req_contents);

    /* setup the client pull */
    ap_snprintf(refresh, PBC_1K-1, "%d;URL=%s", PBC_REFRESH_TIME, scfg->login);


    /* the redirect for requests with POST args are  */
    /* different then reqs with only GET args        */
    /* for GETs:                                     */
    /*   granting request is sent in a cookie and    */
    /*   a simple redirect is used to get the user   */
    /*   to the login server                         */
    /* for POSTs or (POST and GET args)              */
    /*   granting request is still sent in a cookie  */
    /*   redirect is done with javascript in the     */
    /*   body or a button if the user has javascript */
    /*   turned off.  the POST info is in a FORM in  */
    /*   the body of the redirect                    */

    e_g_req_contents = ap_palloc(p, (strlen(g_req_contents) + 3) / 3 * 4 + 1);
    libpbc_base64_encode(p, (unsigned char *) g_req_contents, (unsigned char *) e_g_req_contents, strlen(g_req_contents));

    /* create whole g req cookie */
    ap_snprintf(g_req_cookie, PBC_4K-1, 
                "%s=%s; domain=%s; path=/;%s",
                PBC_G_REQ_COOKIENAME, 
                e_g_req_contents,
                PBC_ENTRPRS_DOMAIN,
                secure);
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
        "g_req length %d cookie: %s", strlen(g_req_cookie), g_req_cookie);

    /* make the pre-session cookie */

    pre_s = (char *) libpbc_get_cookie(p,
                                   scfg->sectext,
                                   (unsigned char *) "presesuser",
                                   PBC_COOKIE_TYPE_PRE_S, 
                                   PBC_CREDS_NONE, 
                                   pre_sess_tok,
                                   (unsigned char *)appsrvid(r), 
                                   appid(r), 
								   NULL,
								   0);
		
    pre_s_cookie = ap_psprintf(p, 
              			"%s=%s; path=%s;%s", 
              			PBC_PRE_S_COOKIENAME,
              			pre_s, 
              			"/",
              			secure);

    ap_table_add(r->headers_out, "Set-Cookie", pre_s_cookie);

    /* load and send the header */
    ap_table_add(r->headers_out, "Set-Cookie", g_req_cookie);
  
    set_no_cache_headers(r);

    /* we handle multipart/form-data by setting a cookie that tells       */
    /* the login server to put up an error page.  now that we can detect  */
    /* multipart/form-data reliably it will be easier to deal with it     */
    if ( ctype && !strncmp(ctype,"multipart/form-data",strlen("multipart/form-data")) ) {

        ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/;%s",
                    PBC_FORM_MP_COOKIENAME, 
                    "1",
                    PBC_ENTRPRS_DOMAIN,
                    secure);
        ap_table_add(r->headers_out, "Set-Cookie", g_req_cookie);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
            "auth_failed_handler: setting Form/Multipart cookie");
    }

    refresh_e = ap_os_escape_path(p, refresh, 0);
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
    if ( !(tenc || lenp) )
        ap_table_add(r->headers_out, "Refresh", refresh_e);
#endif
    ap_send_http_header(r);

    /* now deal with the body */
    if ( (ctype && strncmp(ctype,"multipart/fo",strlen("multipart/fo"))) &&
        (tenc || lenp || r->method_number == M_POST) ) {
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML1);
        ap_rprintf(r, "%s", scfg->login);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML2);
        put_out_post(r);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML3);
        ap_rprintf(r, "%s", scfg->login);
        ap_rprintf(r, "%s", PBC_WEBISO_LOGO);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML4);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_BUTTON);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML5);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML6);
    }
    else {
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
        ap_rprintf(r, "<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
#else
        ap_rprintf(r, "<HTML><HEAD><meta HTTP-EQUIV=\"Refresh\" CONTENT=\"%s\"></HEAD><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n", refresh);
#endif
    }

    return(OK);

}

/*                                                                            */
static int bad_user_handler(request_rec *r) {

  r->content_type = "text/html";
  ap_send_http_header(r);
  ap_rprintf(r, "Unauthorized user.");
  return(OK);

}

/*                                                                            */
static int is_pubcookie_auth(pubcookie_dir_rec *cfg) {
  if ( cfg->creds && cfg->creds != PBC_CREDS_NONE ) {
    return(PBC_TRUE);
  }
  else {
    return(PBC_FALSE);
  }

}

/* figure out the session cookie name                                         */
char *make_session_cookie_name(pool *p, char *cookiename, unsigned char *_appid)
{
  /* 
     we now use JimB style session cookie names
     session cookie names are PBC_S_COOKIENAME_appid 
   */

    char *ptr;
    char *name;

    name = ap_pstrcat(p, cookiename, "_", _appid, NULL);

    ptr = name;
    while(*ptr) {
        if(*ptr == '/')
            *ptr = '_';
        ptr++;
    }

    return name;
}

/*
 * Since we blank out cookies, they're stashed in the notes table.
 * blank_cookie only stashes in the topmost request's notes table, so
 * that's where we'll look.
 *
 * We don't bother with using the topmost request when playing with the
 * headers because only the pointer is copied, anyway.
 */
char *get_cookie(request_rec *r, char *name) {
    const char *cookie_header; 
    char *cookie, *ptr;
    request_rec *mr = top_rrec (r);
    char *name_w_eq;

    /* get cookies */
    if( (cookie_header = ap_table_get(mr->notes, name)) )
        return ap_pstrdup(r->pool, cookie_header);
    if(!(cookie_header = ap_table_get(r->headers_in, "Cookie")))
        return NULL;

    /* add an equal on the end */
    name_w_eq = ap_pstrcat(r->pool, name, "=", NULL);

    /* find the one that's pubcookie */
    if(!(cookie_header = strstr(cookie_header, name_w_eq)))
        return NULL;

    cookie_header += strlen(name_w_eq);

    cookie = ap_pstrdup(r->pool, cookie_header);

    ptr = cookie;
    while(*ptr) {
        if(*ptr == ';')
            *ptr = 0;
        ptr++;
    }

    blank_cookie(r, name);
    return cookie;

}

static void mylog(pool *p, int logging_level, const char *msg)
{
    int apri = APLOG_INFO;

    /* convert pubcookie error level to apache error level */
    if (logging_level == PBC_LOG_ERROR)
        apri = APLOG_ERR|APLOG_NOERRNO;
    else if (logging_level == PBC_LOG_DEBUG_LOW ||
             logging_level == PBC_LOG_DEBUG_VERBOSE ||
             logging_level == PBC_LOG_DEBUG_OUTPUT )
        apri = APLOG_DEBUG|APLOG_NOERRNO;

    ap_log_error(APLOG_MARK, apri, NULL, "%s", msg);
/*    fprintf(stderr, msg); */

}

static void pubcookie_init(server_rec *main_s, pool *p) {
    server_rec                        *s;
    pubcookie_server_rec 	*scfg;
    char 		 	*fname;

    /* initialize each virtual server */
    /* some of the code should be pulled out of the loop */
    for (s = main_s; s != NULL; s=s->next) {

    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config, 
                                                   &pubcookie_module);
    ap_add_version_component(
            ap_pstrcat(p, "mod_pubcookie/", PBC_VERSION_STRING, NULL));

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, s,
        "pubcookie_init: hello");

    /* bail if PubcookieAuthTypes not set */
    if( scfg->authtype_names == NULL ) {
        ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_NOERRNO, s, 
		"PubCookieAuthTypeNames configuration directive must be set!");
	exit(1);
    }

    if (ap_table_get(scfg->configlist, "ssl_key_file") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_NOERRNO, s, 
		"PubCookieSessionKeyFile configuration directive must be set!");
	exit(1);
    }
    if (ap_table_get(scfg->configlist, "ssl_cert_file") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_NOERRNO, s, 
		"PubCookieSessionCertFile configuration directive must be set!");
	exit(1);
    }

    /* old config way */
    /* libpbc_config_init(p, NULL, "mod_pubcookie"); */
    pbc_log_init(p, "mod_pubcookie", NULL, &mylog, NULL);

    pbc_configure_init(p, "mod_pubcookie", 
        &libpbc_apacheconfig_init,
        scfg,
        &libpbc_apacheconfig_getint,
        &libpbc_apacheconfig_getlist,
        &libpbc_apacheconfig_getstring,
        &libpbc_apacheconfig_getswitch);

    if (ap_table_get(scfg->configlist, "granting_cert_file") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_NOERRNO, s, 
            "PubCookieGrantingCertFile configuration directive not set, using %s/%s", 
             PBC_KEY_DIR, "pubcookie_granting.cert");
    }


    /* libpubcookie initialization */
    libpbc_pubcookie_init(p, &scfg->sectext);

    if (!scfg->login) {
        /* if the user didn't explicitly configure a login server,
           let's default to PBC_LOGIN_URI */
        scfg->login = ap_pstrcat(p, PBC_LOGIN_URI, NULL);
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, s,
                     "pubcookie_init(): login from PBC_LOGIN_URI: %s",
                     scfg->login);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, s,
        "pubcookie_init: bye");

    }
}

/*                                                                            */
static void *pubcookie_server_create(pool *p, server_rec *s) {
  pubcookie_server_rec *scfg;
  scfg = (pubcookie_server_rec *) ap_pcalloc(p, sizeof(pubcookie_server_rec));
        
  scfg->configlist = ap_make_table(p, CONFIGLISTGROWSIZE);
  scfg->dirdepth = PBC_DEFAULT_DIRDEPTH;
  scfg->authtype_names = NULL;

  return (void *)scfg;
}

/*                                                                            */
static void *pubcookie_dir_create(pool *p, char *dirspec) {
  pubcookie_dir_rec *cfg;
  cfg = (pubcookie_dir_rec *) ap_pcalloc(p, sizeof(pubcookie_dir_rec));

  cfg->inact_exp = PBC_UNSET_INACT_EXPIRE;
  cfg->hard_exp = PBC_UNSET_HARD_EXPIRE;
  cfg->session_reauth = PBC_UNSET_SESSION_REAUTH;
  cfg->addl_requests = NULL;

  return (void *)cfg;

}

/*                                                                            */
static void *pubcookie_server_merge(pool *p, void *parent, void *newloc) {
    pubcookie_server_rec *scfg;
    pubcookie_server_rec *pscfg = (pubcookie_server_rec *)parent;
    pubcookie_server_rec *nscfg = (pubcookie_server_rec *)newloc;

    scfg = (pubcookie_server_rec *) ap_pcalloc(p, sizeof(pubcookie_server_rec));

    scfg->login = (nscfg->login != NULL) ? 
		nscfg->login : pscfg->login;
    scfg->appsrvid = (nscfg->appsrvid != NULL) ? 
		nscfg->appsrvid : pscfg->appsrvid;
    scfg->dirdepth = nscfg->dirdepth ? 
		nscfg->dirdepth : pscfg->dirdepth;
    scfg->noblank = nscfg->noblank ? 
		nscfg->noblank : pscfg->noblank;
    scfg->authtype_names = nscfg->authtype_names ? 
		nscfg->authtype_names : pscfg->authtype_names;

    scfg->configlist = ap_overlay_tables(p, nscfg->configlist,
                                         pscfg->configlist);

    return (void *)scfg;
}

/*                                                                            */
static void *pubcookie_dir_merge(pool *p, void *parent, void *newloc) {
    pubcookie_dir_rec *cfg;
    pubcookie_dir_rec *pcfg = (pubcookie_dir_rec *) parent;
    pubcookie_dir_rec *ncfg = (pubcookie_dir_rec *) newloc;

    /* cfg->failed doesn't get merged b/c is single use */
    /* cfg->has_granting doesn't get merged b/c is single use */
    cfg = (pubcookie_dir_rec *) ap_pcalloc(p, sizeof(pubcookie_dir_rec));

    cfg->inact_exp = (ncfg->inact_exp == PBC_UNSET_INACT_EXPIRE)
			? pcfg->inact_exp : ncfg->inact_exp;
    cfg->hard_exp = (ncfg->hard_exp == PBC_UNSET_HARD_EXPIRE)
			? pcfg->hard_exp : ncfg->hard_exp;

    cfg->session_reauth = (ncfg->session_reauth == PBC_UNSET_SESSION_REAUTH)
		? pcfg->session_reauth : ncfg->session_reauth;

    /* life is much easier if the default value is zero or NULL */
    cfg->appid = ncfg->appid ? 
		ncfg->appid : pcfg->appid;
    cfg->end_session = ncfg->end_session ? 
		ncfg->end_session : pcfg->end_session;

    if (pcfg->addl_requests) {
	if (ncfg->addl_requests) {
	    cfg->addl_requests = (unsigned char *) ap_pstrcat(p, pcfg->addl_requests, 
                                                 ncfg->addl_requests, NULL);
	} else {
	    cfg->addl_requests = pcfg->addl_requests;
	}
    } else {
	cfg->addl_requests = ncfg->addl_requests;
    }

    cfg->strip_realm = ncfg->strip_realm ?
                       ncfg->strip_realm : pcfg->strip_realm;

    if (ncfg->accept_realms) {
        cfg->accept_realms = ap_pstrdup(p, ncfg->accept_realms);
    } else if (pcfg->accept_realms) {
        cfg->accept_realms = ap_pstrdup(p, pcfg->accept_realms);
    } else {
        cfg->accept_realms = NULL;
    }

    return (void *) cfg;

}

/* the bestest way to deal with default values for things that go thru the    */
/* create/merge gauntlet is to wait until you're ready to use them and then   */
/* see if they've been explicitly set                                         */
void pubcookie_dir_defaults(pubcookie_dir_rec *cfg) {

    if( cfg->inact_exp == PBC_UNSET_INACT_EXPIRE )
        cfg->inact_exp = PBC_DEFAULT_INACT_EXPIRE;
    if( cfg->hard_exp == PBC_UNSET_HARD_EXPIRE )
        cfg->hard_exp = PBC_DEFAULT_HARD_EXPIRE;
}

/* when there is stuff in the server rec with non-zero defaults put them here */
void pubcookie_server_defaults(pubcookie_server_rec *scfg) 
{
    
}
				 
int get_pre_s_from_cookie(request_rec *r)
{
    pubcookie_dir_rec   *cfg;
    pubcookie_server_rec *scfg;
    pbc_cookie_data     *cookie_data = NULL;
    char 		*cookie = NULL;
    pool 		*p = r->pool;

    cfg = (pubcookie_dir_rec *)ap_get_module_config(r->per_dir_config, 
                &pubcookie_module);

    scfg = (pubcookie_server_rec *)ap_get_module_config(r->server->module_config,
                &pubcookie_module);


    if( (cookie = get_cookie(r, PBC_PRE_S_COOKIENAME)) == NULL )
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
      		"get_pre_s_from_cookie: no pre_s cookie, uri: %s\n", 
		r->uri);
    else
        cookie_data = libpbc_unbundle_cookie(p, scfg->sectext, cookie, NULL, 0);

    if( cookie_data == NULL ) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
      		"get_pre_s_from_cookie: can't unbundle pre_s cookie uri: %s\n", 
		r->uri);
	cfg->failed = PBC_BAD_AUTH;
	cfg->redir_reason_no = PBC_RR_BADPRES_CODE;
	return -1;
    }
 
    return((*cookie_data).broken.pre_sess_token);

}

/*                                                                            */
static int pubcookie_user(request_rec *r) {
  pubcookie_dir_rec *cfg;
  pubcookie_server_rec *scfg;
  char *cookie;
  char *isssl = NULL;
  pbc_cookie_data     *cookie_data;
  pool *p = r->pool;
  char *sess_cookie_name;
  char *new_cookie = ap_palloc( r->pool, PBC_1K);
  int cred_from_trans;
  int pre_sess_from_cookie;

  if(!ap_auth_type(r))
    return DECLINED;

  cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                            &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                            &pubcookie_module);

  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
      "pubcookie_user: hello, uri: %s auth_type: %s", r->uri, ap_auth_type(r));

  /* stash the server_rec away so the get_config callbacks know
     which virtual server they are running under
     this uses a global variable, and will definately break under apache2 */
  libpbc_apacheconfig_storeglobal(scfg);


  /* get defaults for unset args */
  pubcookie_dir_defaults(cfg);
  pubcookie_server_defaults(scfg);

  /* if it's basic auth then it's not pubcookie */
  if( strcasecmp(ap_auth_type(r), "basic") == 0 )
    return DECLINED;

  /* get pubcookie creds or bail if not a pubcookie auth_type */
  if( (cfg->creds = pubcookie_auth_type(r)) == PBC_CREDS_NONE )
    return DECLINED;
  
  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
    "pubcookie_user: going to check uri: %s creds: %c", r->uri, cfg->creds);

  /* maybe dump the directory and server recs */
  dump_server_rec(r, scfg);
  dump_dir_rec(r, cfg);

  sess_cookie_name = make_session_cookie_name(p, PBC_S_COOKIENAME, appid(r));

  /* force SSL */
  if (ap_hook_call("ap::mod_ssl::var_lookup", &isssl, p, r->server, 
                 r->connection, r, "HTTPS") && isssl && strcmp (isssl, "on")) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
      		"Not SSL; uri: %s appid: %s", r->uri, appid(r));
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_NOGORS_CODE;
    return OK;
  }

  /* before we check if they hav a valid S or G cookie see if it's a logout */
  if( check_end_session(r) & PBC_END_SESSION_ANY ) { 
      return OK;
  }

  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
    "pubcookie_user: about to look for some cookies; current uri: %s", r->uri);

  /* check if the granting cookie's appid matches.  if not, then act as
     if we don't have one.  This helps if there are any old g cookies */
  cookie_data = NULL;
  if( (cookie = get_cookie(r, PBC_G_COOKIENAME)) && strcmp(cookie, "") != 0 ) {
      cookie_data = libpbc_unbundle_cookie(p, scfg->sectext, cookie, ap_get_server_name(r), 1);
      if( !cookie_data) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
	  		"can't unbundle G cookie; uri: %s\n", r->uri);
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
	  		"cookie is:\n%s\n", cookie);
	  cfg->failed = PBC_BAD_AUTH;
	  cfg->redir_reason_no = PBC_RR_BADG_CODE;
	  return OK;
      }
  }

  /* do we hav a session cookie for this appid? if not check the g cookie */
  if( ! cookie_data || strncasecmp( (const char *) appid(r), 
                                    (const char *) cookie_data->broken.appid, 
                                    sizeof(cookie_data->broken.appid)-1) != 0 ){
    if( !(cookie = get_cookie(r, sess_cookie_name)) || strcmp(cookie,"") == 0 ){

      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
        	"No G or S cookie; uri: %s appid: %s sess_cookie_name: %s", 
		r->uri, appid(r), sess_cookie_name);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_NOGORS_CODE;
      return OK;
    }
    else {  /* hav S cookie */

      cookie_data = libpbc_unbundle_cookie(p, scfg->sectext, cookie, NULL, 0);
      if( ! cookie_data ) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
	  		"can't unbundle S cookie; uri: %s\n", r->uri);
	  cfg->failed = PBC_BAD_AUTH;
	  cfg->redir_reason_no = PBC_RR_BADS_CODE;
	  return OK;
      }
      else {
          cfg->cookie_data = cookie_data;
      }

      /* we tell everyone what authentication check we did */
      r->connection->ap_auth_type = ap_pstrdup(r->pool, ap_auth_type(r));
      r->connection->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);

      /* save the full user/realm for later */
      cfg->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);

      /* check for acceptable realms and strip realm */
      if (1==1) {
          char *tmprealm, *tmpuser;
          tmpuser = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);
          tmprealm = index(tmpuser, '@');
          if (tmprealm) {
              tmprealm[0] = 0;
              tmprealm++;
              r->connection->user = tmpuser;
              ap_table_set(r->subprocess_env, "REMOTE_REALM", tmprealm);
          }
          ap_table_set(r->subprocess_env, "REMOTE_REALM", tmprealm);

          if (cfg->strip_realm == 1) {
             r->connection->user = tmpuser;
          } else {
             r->connection->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);
          }

          if (cfg->accept_realms != NULL) {
              int realmmatched = 0;
              char *thisrealm;
              char *okrealms = ap_pstrdup(r->pool, cfg->accept_realms);
              while (*okrealms && !realmmatched &&
                     (thisrealm=ap_getword_white_nc(r->pool,&okrealms))){
                  if (strcmp(thisrealm,tmprealm) == 0) {
                     realmmatched++;
                  }
              }
              if (realmmatched == 0) {
                 return HTTP_UNAUTHORIZED;
              }
          }
      }

      if( libpbc_check_exp(p, (*cookie_data).broken.create_ts, cfg->hard_exp) == PBC_FAIL ) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
        	"S cookie hard expired; user: %s cookie timestamp: %d timeout: %d now: %d uri: %s\n", 
                (*cookie_data).broken.user, 
                (*cookie_data).broken.create_ts, 
                cfg->hard_exp,
                time(NULL),
                r->uri);
        cfg->failed = PBC_BAD_AUTH;
        cfg->redir_reason_no = PBC_RR_SHARDEX_CODE;
        return OK;
      }

      if( cfg->inact_exp != -1 &&
          libpbc_check_exp(p, (*cookie_data).broken.last_ts, cfg->inact_exp) == PBC_FAIL ) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
        	"S cookie inact expired; user: %s cookie timestamp %d timeout: %d now: %d uri: %s\n", 
                (*cookie_data).broken.user, 
                (*cookie_data).broken.last_ts, 
                cfg->inact_exp,
                time(NULL),
                r->uri);
        cfg->failed = PBC_BAD_AUTH;
        cfg->redir_reason_no = PBC_RR_SINAEX_CODE;
        return OK;
      }

    } /* end if session cookie */

  }
  else { 

    cfg->has_granting = 1;

    clear_granting_cookie(r);
    clear_pre_session_cookie(r);

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
	"pubcookie_user: has granting; current uri is: %s", r->uri);

    /* check pre_session cookie */
    pre_sess_from_cookie = get_pre_s_from_cookie(r);
    if( (*cookie_data).broken.pre_sess_token != pre_sess_from_cookie ) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
      	"pubcookie_user, pre session tokens mismatched, uri: %s", r->uri);
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
      	"pubcookie_user, pre session from G: %d PRE_S: %d, uri: %s", 
	  (*cookie_data).broken.pre_sess_token, pre_sess_from_cookie, r->uri);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_BADPRES_CODE;
      return OK;
    }

    /* the granting cookie gets blanked too early and another login */
    /* server loop is required, this just speeds up that loop */
    if( strncmp(cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0 ) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
          "pubcookie_user: 'speed up that loop' logic; uri is: %s\n", r->uri);

      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_DUMMYLP_CODE;
      return OK;
    }

    r->connection->ap_auth_type = ap_pstrdup(r->pool, ap_auth_type(r));
    r->connection->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);

      /* save the full user/realm for later */
      cfg->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);

      /* check for acceptable realms and strip realm */
      if (1==1) {
          char *tmprealm, *tmpuser;
          tmpuser = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);
          tmprealm = index(tmpuser, '@');
          if (tmprealm) {
              tmprealm[0] = 0;
              tmprealm++;
              r->connection->user = tmpuser;
              ap_table_set(r->subprocess_env, "REMOTE_REALM", tmprealm);
          }
          ap_table_set(r->subprocess_env, "REMOTE_REALM", tmprealm);

          if (cfg->strip_realm == 1) {
             r->connection->user = tmpuser;
          } else {
             r->connection->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);
          }

          if (cfg->accept_realms != NULL) {
              int realmmatched = 0;
              char *thisrealm;
              char *okrealms = ap_pstrdup(r->pool, cfg->accept_realms);
              while (*okrealms && !realmmatched &&
                     (thisrealm=ap_getword_white_nc(r->pool,&okrealms))){
                  if (strcmp(thisrealm,tmprealm) == 0) {
                     realmmatched++;
                  }
              }
              if (realmmatched == 0) {
                 return HTTP_UNAUTHORIZED;
              }
          }
      }

    if( libpbc_check_exp(p, (*cookie_data).broken.create_ts, PBC_GRANTING_EXPIRE) == PBC_FAIL ) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
      		"pubcookie_user: G cookie expired by %ld; user: %s create: %ld uri: %s", time(NULL)-(*cookie_data).broken.create_ts-PBC_GRANTING_EXPIRE, (*cookie_data).broken.user, (*cookie_data).broken.create_ts, r->uri);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_GEXP_CODE;
      return OK;
    }

  }

  /* check appid */
  if( strncasecmp( (const char *) appid(r), 
                   (const char *) (*cookie_data).broken.appid, 
                   sizeof((*cookie_data).broken.appid)-1) != 0 ) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
    		"pubcookie_user: wrong appid; current: %s cookie: %s uri: %s",
		appid(r), (*cookie_data).broken.appid, r->uri);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGAPPID_CODE;
    return OK;
  }

  /* check appsrv id */
  if( strncasecmp( (const char *) appsrvid(r), 
                   (const char *) (*cookie_data).broken.appsrvid, 
                   sizeof((*cookie_data).broken.appsrvid)-1) != 0 ) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
    		"pubcookie_user: wrong app server id; current: %s cookie: %s uri: %s", appsrvid(r), (*cookie_data).broken.appsrvid, r->uri);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGAPPSRVID_CODE;
    return OK;
  }

  /* check version id */
  if( libpbc_check_version(p, cookie_data) == PBC_FAIL ) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
    		"pubcookie_user: wrong version id; module: %d cookie: %d uri: %s", PBC_VERSION, (*cookie_data).broken.version);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGVER_CODE;
    return OK;
  }

  /* check creds */
  if( cfg->creds != cookie_data->broken.creds ) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r, 
    		"pubcookie_user: wrong creds; required: %c cookie: %c uri: %s",
		cfg->creds, (*cookie_data).broken.creds, r->uri);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGCREDS_CODE;
    return OK;
  }

  /* extensions */
  
  /* transcred */
  cookie = get_cookie(r, PBC_CRED_TRANSFER_COOKIENAME);
  cred_from_trans = 1;
  if (!cookie) {
      char *mycookie;

      /* try a locally scoped cookie */
      mycookie = make_session_cookie_name(p, PBC_CRED_COOKIENAME, 
                                          appid(r));

      cred_from_trans = 0; /* not transferring creds */
      cookie = get_cookie(r, mycookie);
  }
  if (cookie) {
      char *blob = ap_palloc(p, strlen(cookie));
      int bloblen;
      char *plain = NULL;
      int plainlen;
      char *krb5ccname;
      FILE *f = NULL;
      int res = 0;

      /* base64 decode cookie */
      if (!libpbc_base64_decode(p, (unsigned char *) cookie, 
                                 (unsigned char *) blob, &bloblen)) {
          ap_log_rerror(APLOG_MARK, APLOG_ERR, r, 
                        "credtrans: libpbc_base64_decode() failed");
          res = -1;
      }
  
      /* decrypt cookie. if credtrans is set, then it's from login server
       to me. otherwise it's from me to me. */
      if (!res && libpbc_rd_priv(p, scfg->sectext, cred_from_trans ? 
                                    ap_get_server_name(r) : NULL, 
									cred_from_trans ? 1 : 0,
                                 blob, bloblen, 
                                 &plain, &plainlen)) {
          ap_log_rerror(APLOG_MARK, APLOG_ERR, r, 
                        "credtrans: libpbc_rd_priv() failed");
          res = -1;
      }

      if (!res && plain) {
          /* sigh, copy it into the memory pool */
          cfg->cred_transfer = ap_palloc(p, plainlen);
          memcpy(cfg->cred_transfer, plain, plainlen);
          cfg->cred_transfer_len = plainlen;
      }

      /* set a random KRB5CCNAME */
      krb5ccname = ap_psprintf(p, "/tmp/k5cc_%d", getpid());
      if (!res) {
          /* save these creds in that file */
          f = ap_pfopen(p, krb5ccname, "w");
          if (!f) {
              ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                            "credtrans: setenv() failed");
              res = -1;
          }
      }
      if (!res && (fwrite(cfg->cred_transfer, cfg->cred_transfer_len, 1, f) != 1)) {
          ap_log_rerror(APLOG_MARK, APLOG_ERR, r, 
                        "credtrans: setenv() failed");
          res = -1;
      }

      if (f) {
          ap_pfclose(p, f);
      }

      if (cred_from_trans) {
          clear_transfer_cookie(r);
      }
  }

  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
      "pubcookie_user: everything is o'tay; current uri is: %s", r->uri);

  return OK;

}

/*                                                                            */
int pubcookie_authz(request_rec *r) {
    pubcookie_dir_rec *cfg;
    pubcookie_server_rec *scfg;

    cfg=(pubcookie_dir_rec *)ap_get_module_config(r->per_dir_config,
                                           &pubcookie_module);
    scfg=(pubcookie_server_rec *)ap_get_module_config(r->server->module_config,
                                            &pubcookie_module);

    if( !is_pubcookie_auth(cfg) ) 
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
    		"pubcookie_authz: hello");

    if(cfg->failed) {         /* pubcookie_user has failed so pass to typer */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
      		"pubcookie_authz: failed: %d", cfg->failed);
        return OK;
    }

    /* if it's a pubcookie logout don't do any authz, skip to pubcookie_typer */
    if( check_end_session(r) & PBC_END_SESSION_ANY ) { 
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
      		"pubcookie_authz: is a logout so no authz");
        return OK;
    }

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r, 
    		"pubcookie_authz: say declined");

    /* declined means that other authorization modules will be applied */
    return DECLINED;

}

/*                                                                            */
static int pubcookie_typer(request_rec *r) {
  pubcookie_dir_rec *cfg;
  pubcookie_server_rec *scfg;
  unsigned char *cookie;
  int first_time_in_session = 0;
  char *new_cookie = ap_palloc( r->pool, PBC_1K);

  if(!ap_auth_type(r))
    return DECLINED;

  cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                            &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                            &pubcookie_module);

  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
		"in typer, creds=0x%x",(int)cfg->creds);

  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;

  if(!ap_requires(r)) {
    ap_log_reason("pubcookie auth configured with no requires lines", r->uri, r);
    return SERVER_ERROR;
  }

  if( cfg->has_granting ) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
      		"pubcookie_typer: coming in with granting");
    first_time_in_session = 1;
    cfg->has_granting = 0;
  }

  /* if the inactivity timeout is turned off don't send a session cookie 
     everytime, but be sure to send a session cookie if it's the first time
     in the app
   */

  if(!cfg->failed) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
      			"pubcookie_typer: no failure");

    if( check_end_session(r) & PBC_END_SESSION_REDIR ) { 
      r->handler = PBC_END_SESSION_REDIR_HANDLER;
      return OK;
    }
    else if( check_end_session(r) & PBC_END_SESSION_ANY ) { 
      clear_session_cookie(r);
    }
    else if( cfg->inact_exp > 0 || first_time_in_session ) {
      set_session_cookie(r, first_time_in_session);
    }
    return DECLINED;
  } else if(cfg->failed == PBC_BAD_AUTH) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
      			"pubcookie_typer: bad auth");
    r->handler = PBC_AUTH_FAILED_HANDLER;
    return OK;
  } else if (cfg->failed == PBC_BAD_USER) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
      			"pubcookie_typer: bad user");
    r->handler = PBC_BAD_USER_HANDLER;
    return OK;
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
      			"pubcookie_typer: unknown failure");
    return DECLINED;
  }

} /* pubcookie_typer */

static int pubcookie_fixups(request_rec *r)
{
    pubcookie_dir_rec *cfg;
    table *e = r->subprocess_env;

    /* here we set any additional environment variables for the client */

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                                     &pubcookie_module);
    
    if (cfg->cred_transfer) {
        char *krb5ccname = ap_psprintf(r->pool, "/tmp/k5cc_%d", getpid());
    
        ap_table_setn(e, "KRB5CCNAME", krb5ccname);
    }

    return OK;
}

/*                                                                            */
static int pubcookie_hparse(request_rec *r)
{
    char *cookies;
    char *nextcookie;

    if (! (cookies = (char *)ap_table_get (r->headers_in, "Cookie")))
        return OK;
    cookies = ap_pstrdup (r->pool, cookies);

    nextcookie = cookies;
    while (nextcookie) {
        char *c = nextcookie;

        nextcookie = strchr (c, ';');
        if( nextcookie != 0 ) {
            *nextcookie++ = '\0';
            while (*nextcookie && *nextcookie == ' ')
                ++nextcookie;
        }
        /* the module might be run on the login server don't blank g req */
        if( strncasecmp(c, PBC_G_REQ_COOKIENAME, sizeof(PBC_G_REQ_COOKIENAME) - 1) &&
               ( !strncasecmp(c, PBC_G_COOKIENAME, sizeof(PBC_G_COOKIENAME) - 1) ||
                 !strncasecmp(c, PBC_PRE_S_COOKIENAME, sizeof(PBC_PRE_S_COOKIENAME) - 1) ||
                 !strncasecmp(c, PBC_S_COOKIENAME, sizeof(PBC_S_COOKIENAME) - 1) )) {
            char *s = strchr(c, '=');
            if (s) {
                *s = '\0';
                get_cookie(r, c);
            }
        }
    }

    return OK;
}

/*                                                                            */
const char *pubcookie_set_inact_exp(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_dir_rec   *cfg = (pubcookie_dir_rec *) mconfig;
    char                *err_string;
  
    if((cfg->inact_exp = atoi(v)) < 0 && cfg->inact_exp != -1 ) {
        return "PUBCOOKIE: Could not convert inactivity expire parameter to nonnegative number.";
    }

    /* how to turn off inactivity checking */
    if( cfg->inact_exp == -1 ) {
        return NULL;
    }

    /* check for valid range */
    if( cfg->inact_exp < PBC_MIN_INACT_EXPIRE ) {
        err_string = ap_psprintf(cmd->pool, "PUBCOOKIE: inactivity expire parameter less then allowed minimum of %d, requested %d.", PBC_MIN_INACT_EXPIRE, cfg->inact_exp);
        return(err_string);
    }

    return NULL;
}

/**
 *  handle the PubCookieHardExpire directive
 *  does some range checking
 */
const char *pubcookie_set_hard_exp(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_dir_rec   *cfg = (pubcookie_dir_rec *) mconfig;
    char                *err_string;
  
    if((cfg->hard_exp = atoi(v)) <= 0) {
        return("PUBCOOKIE: PubcookieHardExpire should be nonnegative integer.");
    }
    else if(cfg->hard_exp > PBC_MAX_HARD_EXPIRE ) {
        err_string = ap_psprintf(cmd->pool, "PUBCOOKIE: Hard expire parameter greater then allowed maximium of %d, requested %d.", PBC_MAX_HARD_EXPIRE, cfg->hard_exp);
        return(err_string);
    }
    else if(cfg->hard_exp < PBC_MIN_HARD_EXPIRE ) {
        err_string = ap_psprintf(cmd->pool, "PUBCOOKIE: Hard expire parameter less then allowed minimum of %d, requested %d.", PBC_MIN_HARD_EXPIRE, cfg->hard_exp);
        return(err_string);
    }

    return NULL;
}

/**
 *  handle the PubCookieLogin directive
 *  we do a little checking to make sure the url is correctly formatted.
 */
const char *pubcookie_set_login(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec           *s = cmd->server;
    uri_components 	 uptr;
    char                 *err_string;
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
                                 ap_get_module_config(s->module_config,
                                 &pubcookie_module);
    
    if( ap_parse_uri_components(cmd->pool, v, &uptr) != HTTP_OK ) {
        err_string = ap_psprintf(cmd->pool, "PUBCOOKIE: PubCookieLogin not correctly formatted URL.");
        return(err_string);
    }

#ifdef PORT80_TEST
    if( uptr.scheme == NULL || strncmp(uptr.scheme, "http", 4) != 0 ) {
        err_string = ap_psprintf(cmd->pool, "PUBCOOKIE: PubCookieLogin must start with http:// or https://");
        return(err_string);
    }
#else
    /* force ssl */
    if( uptr.scheme == NULL || strcmp(uptr.scheme, "https") != 0 ) {
        uptr.scheme = ap_pstrdup(cmd->pool, "https");
    }
#endif

    /* if the url has no path add a '/' */
    if( uptr.path == NULL )
        uptr.path = ap_pstrdup(cmd->pool, "/");
    
    scfg->login = ap_unparse_uri_components(cmd->pool, &uptr, 0);
    ap_table_set(scfg->configlist, "login_uri", (char *)&uptr);

    return NULL;
}

/**
 *  handle the PubCookieDomain directive
 */
const char *pubcookie_set_domain(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec           *s = cmd->server;
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
                                 ap_get_module_config(s->module_config,
                                 &pubcookie_module);
    ap_table_set(scfg->configlist, "enterprise_domain", v);
    return NULL;
}

/**
 *  handle the PubCookieKeyDir directive
 */
const char *pubcookie_set_keydir(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec           *s = cmd->server;
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
                                 ap_get_module_config(s->module_config,
                                 &pubcookie_module);
    ap_table_set(scfg->configlist, "keydir", v);
    return NULL;
}

/*                                                                            */
const char *pubcookie_set_appid(cmd_parms *cmd, void *mconfig, unsigned char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;
    unsigned char *c;

    cfg->appid = ap_palloc (cmd->pool, strlen ( (const char *) v) * 3 + 1);
    for (c = cfg->appid; *v; ++v) {
        switch (*v) {
            case ' ': *c++ = '+'; break;
            case '%': *c++ = '%'; *c++ = '2'; *c++ = '5'; break;
            case '&': *c++ = '%'; *c++ = '2'; *c++ = '6'; break;
            case '+': *c++ = '%'; *c++ = '2'; *c++ = 'B'; break;
            case ':': *c++ = '%'; *c++ = '3'; *c++ = 'A'; break;
            case ';': *c++ = '%'; *c++ = '3'; *c++ = 'B'; break;
            case '=': *c++ = '%'; *c++ = '3'; *c++ = 'D'; break;
            case '?': *c++ = '%'; *c++ = '3'; *c++ = 'F'; break;
            default: *c++ = *v; break;
        }
    }
    *c = '\0';
    return NULL;
}

const char *pubcookie_add_request(cmd_parms *cmd, 
                                  void *mconfig, 
				  unsigned char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;

    cfg = (pubcookie_dir_rec *) mconfig;
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
							 &pubcookie_module);

    if (!scfg) return "pubcookie_add_request(): scfg is NULL ?!";

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, s, 
		"pubcookie_add_request(): %s", v);
    cfg->addl_requests = (unsigned char *) ap_pstrcat(cmd->pool, 
                                    cfg->addl_requests ? cfg->addl_requests : 
                                    (unsigned char *) "",
                                    "&", v, NULL);
    return NULL;

}

const char *pubcookie_accept_realms(cmd_parms *cmd,
                                   void *mconfig,
                                   unsigned char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;

    cfg = (pubcookie_dir_rec *) mconfig;
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                         &pubcookie_module);

    if (!scfg) return "pubcookie_accept_realms(): scfg is NULL ?!";

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, s,
                "pubcookie_accept_realms(): %s", v);
    cfg->accept_realms =  ap_pstrcat(cmd->pool,
                             cfg->accept_realms ? cfg->accept_realms :
                             "", " ", v, NULL);
    return NULL;
}

const char *pubcookie_strip_realm(cmd_parms *cmd, void *mconfig, int f) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if(f != 0) {
        cfg->strip_realm = 1;
    } else {
        cfg->strip_realm = 0;
    }
    return NULL;
}

/*                                                                            */
const char *pubcookie_set_appsrvid(cmd_parms *cmd, void *mconfig, unsigned char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    unsigned char *c;

    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);

    scfg->appsrvid = ap_palloc (cmd->pool, strlen ( (const char *) v) * 3 + 1);
    for (c = scfg->appsrvid; *v; ++v) {
        switch (*v) {
              case ' ': *c++ = '+'; break;
              case '%': *c++ = '%'; *c++ = '2'; *c++ = '5'; break;
              case '&': *c++ = '%'; *c++ = '2'; *c++ = '6'; break;
              case '+': *c++ = '%'; *c++ = '2'; *c++ = 'B'; break;
              case ':': *c++ = '%'; *c++ = '3'; *c++ = 'A'; break;
              case ';': *c++ = '%'; *c++ = '3'; *c++ = 'B'; break;
              case '=': *c++ = '%'; *c++ = '3'; *c++ = 'D'; break;
              case '?': *c++ = '%'; *c++ = '3'; *c++ = 'F'; break;
              default: *c++ = *v; break;
        }
    }
    *c = '\0';
    return NULL;
}

/*                                                                            */
const char *pubcookie_set_dirdepth(cmd_parms *cmd, void *mconfig, unsigned char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;

    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);

    if((scfg->dirdepth = atoi( (const char *) v)) < 0 ) {
        return "PUBCOOKIE: Could not convert Directory Depth for AppID parameter to nonnegative number.";
    }
    
    /* externally we count directories but internally we cound slashes
                      external    internal
          /            == 0          1
          /blah/       == 1          2
          /blah/blong/ == 2          3
       and internally zero is 'unset'
     */
    (scfg->dirdepth)++;

    return NULL;
}

/**
 *  handle the PubCookieGrantingCertFile directive
 */
const char *pubcookie_set_g_certf(cmd_parms *cmd, void *mconfig, char *v) {

    pubcookie_server_rec * scfg = (pubcookie_server_rec *)
        ap_get_module_config(cmd->server->module_config, &pubcookie_module);

    ap_table_set(scfg->configlist, "granting_cert_file", v);
    return NULL;
}

/**
 *  handle the PubCookieSessionKeyFile directive
 */
const char *pubcookie_set_s_keyf(cmd_parms *cmd, void *mconfig, char *v) {

    pubcookie_server_rec * scfg = (pubcookie_server_rec *)
        ap_get_module_config(cmd->server->module_config, &pubcookie_module);

    ap_table_set(scfg->configlist, "ssl_key_file", v);
    return NULL;
}

/**
 *  handle the PubCookieSessionCertFile directive
 */
const char *pubcookie_set_s_certf(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_server_rec * scfg = (pubcookie_server_rec *)
        ap_get_module_config(cmd->server->module_config, &pubcookie_module);

    ap_table_set(scfg->configlist, "ssl_cert_file", v);
    return NULL;
}

/**
 *  handle the PubCookieCryptKeyFile directive
 *
 *  I don't think this is actually used anywhere.  I think it always uses
 *  keydir/hostname instead. 
 */
const char *pubcookie_set_crypt_keyf(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_server_rec * scfg = (pubcookie_server_rec *)
        ap_get_module_config(cmd->server->module_config, &pubcookie_module);

    ap_table_set(scfg->configlist, "crypt_key", v);
    return NULL;
}

/** 
 * handle the PubCookieEgdDevice directive
 */

const char *pubcookie_set_egd_device( cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_server_rec * scfg = (pubcookie_server_rec *)
        ap_get_module_config(cmd->server->module_config, &pubcookie_module);

    ap_table_set(scfg->configlist, "egd_socket", v);
    return NULL;
}

/*                                                                            */
const char *set_session_reauth(cmd_parms *cmd, void *mconfig, unsigned char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if (!v) cfg->session_reauth = 0;
    else if (!strcasecmp(v, "on")) cfg->session_reauth = 1;
    else if (!strcasecmp(v, "off")) cfg->session_reauth = 0;
    else cfg->session_reauth = atoi((const char *) v);
    if (cfg->session_reauth<0) cfg->session_reauth = 1;
    return NULL;
}

/* sets flag to remove session cookie                                         */
/*  can also set the action to redirecto the login server                     */
const char *set_end_session(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    cfg->end_session = ap_pstrdup(cmd->pool, v);

    return NULL;

}


/* allow admin to set a "dont blank the cookie" mode for proxy with pubcookie */
const char *pubcookie_set_no_blank(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    ap_pool *p = cmd->pool;

    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);

    scfg->noblank = 1;

    return NULL;

}

/**
 * used to give more debugging, does nothing now
 * @param cmd - command record
 * @param mconfig - module configuration
 * @param f - int
 * @returns NULL 
 */
const char *set_super_debug(cmd_parms *cmd, void *mconfig, int f) {
    server_rec *s = cmd->server;

    ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_NOERRNO, s, 
		"PubcookieSuperDebug deprecated, please remove.");

    return NULL;

}

/*                                                                            */
const char *pubcookie_set_no_ssl_ok(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    cfg->non_ssl_ok = 1;

    return NULL;

}

/**
 * sets the text names for auth types
 * @param cmd - command record
 * @param mconfig - module configuration
 * @param args - aguments for directive
 * @returns NULL 
 */
const char *set_authtype_names(cmd_parms *cmd, void *mconfig, char *args) {
    server_rec           *s = cmd->server;
    pubcookie_server_rec *scfg;
    ap_pool              *p = cmd->pool;

    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);

    scfg->authtype_names = ap_pstrdup(cmd->pool, args);

    return NULL;

}

/*                                                                            */
command_rec pubcookie_commands[] = {
    {"PubCookieInactiveExpire", pubcookie_set_inact_exp, NULL, OR_OPTIONS|OR_AUTHCFG, TAKE1,
     "Set the inactivity expire time for PubCookies."},
    {"PubCookieHardExpire", pubcookie_set_hard_exp, NULL, OR_OPTIONS|OR_AUTHCFG, TAKE1,
     "Set the hard expire time for PubCookies."},
    {"PubCookieLogin", pubcookie_set_login, NULL, RSRC_CONF, TAKE1,
     "Set the login page for PubCookies."},
    {"PubCookieDomain", pubcookie_set_domain, NULL, RSRC_CONF, TAKE1,
     "Set the domain for PubCookies."},
    {"PubCookieKeyDir", pubcookie_set_keydir, NULL, RSRC_CONF, TAKE1,
     "Set the location of PubCookie encryption keys."},

    {"PubCookieGrantingCertfile", pubcookie_set_g_certf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the certfile for Granting PubCookies."},
    {"PubCookieSessionKeyfile", pubcookie_set_s_keyf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the keyfile for Session PubCookies."},
    {"PubCookieSessionCertfile", pubcookie_set_s_certf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the certfile for Session PubCookies."},
    {"PubCookieCryptKeyfile", pubcookie_set_crypt_keyf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the encryption keyfile for PubCookies."},
    {"PubCookieEgdDevice", pubcookie_set_egd_device, NULL, RSRC_CONF, TAKE1,
     "Set the name of the EGD Socket if needed for randomness."},

    {"PubCookieNoBlank", pubcookie_set_no_blank, NULL, RSRC_CONF, TAKE1,
     "Do not blank cookies."},
    {"PubCookieAuthTypeNames", set_authtype_names, NULL, RSRC_CONF, RAW_ARGS,
     "Sets the text names for authtypes."},

    {"PubCookieAppID", pubcookie_set_appid, NULL, OR_OPTIONS|OR_AUTHCFG, TAKE1,
     "Set the name of the application."},
    {"PubCookieAppSrvID", pubcookie_set_appsrvid, NULL, RSRC_CONF, TAKE1,
     "Set the name of the server(cluster)."},
    {"PubCookieDirDepthforAppID", pubcookie_set_dirdepth, NULL, RSRC_CONF, TAKE1,
     "Specify the Directory Depth for generating default AppIDs."},

    {"PubcookieSessionCauseReAuth", set_session_reauth, NULL, OR_AUTHCFG, TAKE1,
     "Force reauthentication for new sessions and session timeouts"},
    {"PubcookieEndSession", set_end_session, NULL, OR_AUTHCFG, RAW_ARGS,
     "End application session and possibly login session"},
    {"PubCookieAddlRequest", pubcookie_add_request, NULL, OR_AUTHCFG, ITERATE,
     "Send the following options to the login server along with authentication requests"},
    {"PubCookieAcceptRealm", pubcookie_accept_realms, NULL, OR_OPTIONS|OR_AUTHCFG, ITERATE,
     "Only accept realms in this list"},
    {"PubCookieStripRealm", pubcookie_strip_realm, NULL, OR_OPTIONS|OR_AUTHCFG, FLAG,
     "Strip the realm (and set the REMOTE_REALM envirorment variable)"},

    {"PubCookieSuperDebug", set_super_debug, NULL, OR_AUTHCFG, FLAG,
     "Deprecated, do not use"},

/* maybe for future exploration
    {"PubCookieNoSSLOK", pubcookie_set_no_ssl_ok, NULL, OR_AUTHCFG, TAKE1,
     "Allow session to go non-ssl."},
*/
    {NULL}
};

/*                                                                            */
handler_rec pubcookie_handlers[] = {
    { PBC_STOP_THE_SHOW_HANDLER, stop_the_show_handler},
    { PBC_AUTH_FAILED_HANDLER, auth_failed_handler},
    { PBC_END_SESSION_REDIR_HANDLER, do_end_session_redirect_handler},
    { PBC_BAD_USER_HANDLER, bad_user_handler},
    { NULL }
};

/*                                                                            */
module pubcookie_module = {
    STANDARD_MODULE_STUFF,
    pubcookie_init,              /* initializer */
    pubcookie_dir_create,        /* dir config creater */
    pubcookie_dir_merge,         /* dir merger --- default is to override */
    pubcookie_server_create,     /* server config */
    pubcookie_server_merge,      /* merge server config */
    pubcookie_commands,          /* command table */
    pubcookie_handlers,          /* handlers */
    NULL,                        /* filename translation */
    pubcookie_user,              /* check authentication */
    pubcookie_authz,             /* check authorization */
    NULL,                        /* check access */
    pubcookie_typer,             /* type_checker */
    pubcookie_fixups,            /* fixups */
    NULL,                        /* logger */
    pubcookie_hparse             /* header parser */
#ifdef EAPI
    ,
    NULL,                        /* EAPI: add_module */
    NULL,                        /* EAPI: remove_module */
    NULL,                        /* EAPI: rewrite_command */
    NULL                         /* EAPI: new_connection */
#endif
};

