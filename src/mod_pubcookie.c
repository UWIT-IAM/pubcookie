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

    this is the pubcookie apache module

 */

/*
    $Id: mod_pubcookie.c,v 1.79 2002-06-05 16:52:29 greenfld Exp $
 */

/* apache includes */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"

/* ssleay lib stuff */
#include <pem.h>
#include <des.h>
#include <rand.h>
#include <err.h>

/* pubcookie stuff */
#include "pbc_myconfig.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

/* system stuff */
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

/* misc prototype */
char *make_session_cookie_name(pool *, unsigned char *);

module pubcookie_module;

typedef struct {
  char                  *g_certfile;
  char                  *s_keyfile;
  char                  *s_certfile;
  char                  *crypt_keyfile;
  md_context_plus       *session_sign_ctx_plus;
  md_context_plus       *session_verf_ctx_plus;
  md_context_plus       *granting_verf_ctx_plus;
  crypt_stuff           *c_stuff;
  int                   serial_g_seen;
  int                   serial_s_seen;
  int                   serial_s_sent;
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
  int           super_debug;
  int           redir_reason_no;
  int           session_reauth;
} pubcookie_dir_rec;

void dump_server_rec(pubcookie_server_rec *scfg) {
    libpbc_debug("super-debug: dump_server_rec:\n\
		g_certfile: %s\n\
		s_keyfile: %s\n\
		s_certfile: %s\n\
		crypt_keyfile: %s\n\
		session_sign_ctx_plus: %s\n\
		session_verf_ctx_plus: %s\n\
		granting_verf_ctx_plus: %s\n\
		c_stuff: %s\n\
		serial_g_seen: %d\n\
		serial_s_seen: %d\n\
		serial_s_sent: %d\n\
		dirdepth: %d\n\
		noblank: %d\n\
		login: %s\n\
		appsrvid: %s\n\
		authtype_names: %s\n", 
  		(scfg->g_certfile == NULL ? "" : scfg->g_certfile),
  		(scfg->s_keyfile == NULL ? "" : scfg->s_keyfile),
  		(scfg->s_certfile == NULL ? "" : scfg->s_certfile),
  		(scfg->crypt_keyfile == NULL ? "" : scfg->crypt_keyfile),
  		(scfg->session_sign_ctx_plus == NULL ? "unset" : "set"),
  		(scfg->session_verf_ctx_plus == NULL ? "unset" : "set"),
  		(scfg->granting_verf_ctx_plus == NULL ? "unset" : "set"),
  		(scfg->c_stuff == NULL ? "unset" : "set"),
		scfg->serial_g_seen, 
		scfg->serial_s_seen, 
		scfg->serial_s_sent, 
		scfg->dirdepth, 
		scfg->noblank, 
  		(scfg->login == NULL ? "" : scfg->login),
  		(scfg->appsrvid == NULL ? "" : (char *)scfg->appsrvid),
  		(scfg->authtype_names == NULL ? "" : (char *)scfg->authtype_names));

}

void dump_dir_rec(pubcookie_dir_rec *cfg) {
    libpbc_debug("super-debug: dump_dir_rec:\n\
		inact_exp: %d\n\
                hard_exp: %d\n\
                failed: %d\n\
                has_granting: %d\n\
                non_ssl_ok: %d\n\
		appid: %s\n\
                creds: %c\n\
		super_debug: %d\n\
                end_session: %s\n\
                redir_reason_no: %d\n\
                session_reauth: %d\n",
  		cfg->inact_exp,
  		cfg->hard_exp,
  		cfg->failed,
  		cfg->has_granting,
  		cfg->non_ssl_ok,
  		(cfg->appid == NULL ? "" : (char *)cfg->appid),
  		cfg->creds,
		cfg->super_debug, 
  		(cfg->end_session == NULL ? "" : (char *)cfg->end_session),
  		cfg->redir_reason_no,
  		cfg->session_reauth);

}

/*                                                                            */
int put_out_post(request_rec *r) {
   char argsbuffer[HUGE_STRING_LEN];
   int retval;

   /* checkout http_protocols.c for reading the body info */
#ifdef APACHE1_2
   if ((retval = setup_client_block(r, REQUEST_CHUNKED_ERROR)))
        return retval;

   if (should_client_block(r)) {
        int len_read;

        hard_timeout("copy script args", r);

        while ((len_read =
                get_client_block(r, argsbuffer, HUGE_STRING_LEN)) > 0) {
            reset_timeout(r);
            if (rwrite(argsbuffer, len_read, r) < len_read) {
                /* something went wrong writing, chew up the rest */
                while (get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0) {
                    /* dump it */
                }
                break;
            }
        }

        kill_timeout(r);
#else
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
                while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0) {
                    /* dump it */
                }
                break;
            }
        }

        ap_kill_timeout(r);
#endif
    }
    return(1);

}

/* make-up the token to be used to bind the granting cookie and pre-session   */
int get_pre_s_token() {
    return(42);

}

/*                                                                            */
unsigned char *get_app_path(request_rec *r, const char *path) {
    char *path_out;
    int truncate;
    pool *p = r->pool;
    pubcookie_server_rec *scfg;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                         &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);
#endif

#ifdef APACHE1_2
    if( scfg->dirdepth ) {
        if( scfg->dirdepth < count_dirs(path) )
            truncate = scfg->dirdepth;
        else
            truncate = count_dirs(path);
        path_out = make_dirstr(p, path, truncate);
    }
    else {
        path_out = make_dirstr(p, path, count_dirs(path));
    }
#else
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
#endif

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
            ret = ret | PBC_END_SESSION_REDIR_MASK;
        }
        if( strcasecmp(word, PBC_END_SESSION_ARG_CLEAR_L) == 0 ) {
            ret = ret | PBC_END_SESSION_CLEAR_L_MASK 
		      | PBC_END_SESSION_REDIR_MASK;
        }
        else if( strcasecmp(word, PBC_END_SESSION_ARG_ON) == 0 ) {
            ret = ret | PBC_END_SESSION_MASK;
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
    int                       i = 1;
    
    scfg=(pubcookie_server_rec *)ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);
    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    type_names = scfg->authtype_names;
    auth_type = ap_auth_type(r);

    /* check list of pubcookie auth_types */
    while( type_names != NULL && *type_names != '\0' &&
		 (word = ap_getword_conf(p, &type_names)) ) {
        if( strcasecmp(word, auth_type) == 0 ) 
            return(i+48);
        i++;
    }

    if( strcasecmp(PBC_DEFAULT_AUTHTYPE, auth_type) == 0 ) 
        return(PBC_CREDS_DEFAULT);
    
    /* request isn't pubcookie */
    return(PBC_CREDS_NONE);

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

#ifdef APACHE1_2
    cfg = (pubcookie_dir_rec *) get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                         &pubcookie_module);
#else
    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);
#endif

    if( cfg->appid )
        return(cfg->appid);
    else
#ifdef APACHE1_2
    {
	char *uri = pstrdup (r->pool, rmain->unparsed_uri);
	char *c = uri;
	/* go past the scheme */
	while (*c && *c != ':' && *c != '/' && *c != '?' && *c != '#')
	    ++c;
	if (*c == '?' || *c == '#') {
	    /* we didn't find a scheme, but did find query or frag - done */
	    *c = '\0';
	} else if (*c == '/') {
	    /* no scheme, look for query or frag */
	    while (*c && *c != '?' && *c != '#')
		++c;
	    *c = '\0';
	} else if (*c && *c++ == ':' && *c++ == '/' && *c++ == '/') {
	    /* looks like a scheme, go past site */
	    while (*c && *c != '/' && *c != '?' && *c != '#')
		++c;
	    if (*c == '/') {
		/* found the site, chop it and the scheme off */
		uri = c;
		/* now look for query or frag */
		while (*c && *c != '?' && *c != '#')
		    ++c;
		*c = '\0';
	    }
	}
        return get_app_path(r, uri);
    }
#else
        return get_app_path(r, rmain->parsed_uri.path);
#endif

}

/* figure out the appsrvid                                                   */
unsigned char *appsrvid(request_rec *r)
{
    pubcookie_server_rec	*scfg;
    pubcookie_dir_rec		*cfg;

#ifdef APACHE1_2
    cfg = (pubcookie_dir_rec *) get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                         &pubcookie_module);
#else
    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);
#endif

    if( scfg->appsrvid )
        return(scfg->appsrvid);
    else
        /* because of multiple passes through don't use r->hostname() */
#ifdef APACHE1_2
        return (unsigned char *) pstrdup(r->pool, get_server_name(r));
#else
        return (unsigned char *) ap_pstrdup(r->pool, ap_get_server_name(r));
#endif

}

/* make sure agents don't cache the redirect */
void set_no_cache_headers(request_rec *r) {

    ap_table_set(r->headers_out, "Expires", ap_gm_timestr_822(r->pool, 
		r->request_time));
    ap_table_set(r->headers_out, "Cache-Control", "no-cache");
    ap_table_set(r->headers_out, "Pragma", "no-cache");

}

/* make session cookie */
void set_session_cookie(request_rec *r) {
    pubcookie_dir_rec    *cfg;
    pubcookie_server_rec *scfg;
    char                 *new_cookie;
    unsigned char        *cookie;

    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg=(pubcookie_server_rec *) ap_get_module_config(r->server->module_config, 					 &pubcookie_module);

    cookie = libpbc_get_cookie_p(r->pool, 
                                   (unsigned char *)r->connection->user, 
                                   PBC_COOKIE_TYPE_S, 
                                   cfg->creds, 
                                   scfg->serial_s_sent++, 
                                   (unsigned char *)appsrvid(r), 
                                   appid(r), 
                                   scfg->session_sign_ctx_plus, 
                                   scfg->c_stuff);

#ifdef PORT80_TEST
    new_cookie = ap_psprintf(r->pool, "%s=%s; domain=%s; path=%s;", 
#else
    new_cookie = ap_psprintf(r->pool, "%s=%s; domain=%s; path=%s; secure", 
#endif
              make_session_cookie_name(r->pool, appid(r)),
              cookie, 
              ap_get_server_name(r),
              "/");

    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);

}

void clear_session_cookie(request_rec *r) {
    char   *new_cookie;

#ifdef PORT80_TEST
    new_cookie = ap_psprintf(r->pool, 
		"%s=%s; domain=%s; path=/; expires=%s;",
#else
    new_cookie = ap_psprintf(r->pool, 
		"%s=%s; domain=%s; path=/; expires=%s; secure", 
#endif
                make_session_cookie_name(r->pool, appid(r)), 
	        PBC_CLEAR_COOKIE,
                ap_get_server_name(r),
                EARLIEST_EVER);

    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);

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

    if(cfg->super_debug)
        libpbc_debug("super-debug: do_end_session_redirect_handler: hello\n");
      
    r->content_type = "text/html";
    clear_session_cookie(r);
    set_no_cache_headers(r);

    ap_send_http_header(r);

    refresh = ap_psprintf(r->pool, "%d;URL=%s?%s=%d&%s=%s&%s=%s", 
		PBC_REFRESH_TIME, 
		scfg->login,
		PBC_GETVAR_LOGOUT_ACTION,
                (check_end_session(r) & PBC_END_SESSION_CLEAR_L_MASK ?
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
#ifdef APACHE1_2
    if(table_get(mr->notes, name) ||
        !(cookie_header = table_get(r->headers_in, "Cookie")))
        return 0;

    /* if we aint got an authtype they we definately aint pubcookie */
    /* then again, we want to always blank cookies */
    /* if(!auth_type(r))                           */
    /*   return DECLINED;                          */

    /* add an equal on the end */
    name_w_eq = pstrcat(r->pool, name, "=", NULL);
#else
    if(ap_table_get(mr->notes, name) ||
        !(cookie_header = ap_table_get(r->headers_in, "Cookie")))
      return 0;

    /* if we aint got an authtype they we definately aint pubcookie */
    /* then again, we want to always blank cookies */
    /* if(!ap_auth_type(r))                        */
    /*   return DECLINED;                          */

    /* add an equal on the end */
    name_w_eq = ap_pstrcat(r->pool, name, "=", NULL);
#endif

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
#ifdef APACHE1_2
    c2 = pstrdup (mr->pool, cookie);
#else
    c2 = ap_pstrdup (mr->pool, cookie);
#endif
    if( (ptr = strchr (c2, ';')) )
        *ptr = '\0';
#ifdef APACHE1_2
    table_set (mr->notes, name, c2);
#else
    ap_table_set (mr->notes, name, c2);
#endif

    ptr = cookie;
    while(*ptr) {
        if(*ptr == ';')
            break;
        *ptr = PBC_X_CHAR;
        ptr++;
    }

#ifdef APACHE1_2
    table_set(r->headers_in, "Cookie", cookie_header);
#else
    ap_table_set(r->headers_in, "Cookie", cookie_header);
#endif

    return (int)ptr;

}

/* Herein we deal with the redirect of the request to the login server        */
/*    if it was only that simple ...                                          */
static int auth_failed(request_rec *r) {
#ifdef APACHE1_2
    char                 *tmp = palloc(r->pool, PBC_1K);
    char                 *refresh = palloc(r->pool, PBC_1K);
    char                 *pre_s = palloc(r->pool, PBC_1K);
    char                 *pre_s_cookie = palloc(r->pool, PBC_1K);
    char                 *g_req_cookie = palloc(r->pool, PBC_4K);
    char                 *g_req_contents = palloc(r->pool, PBC_4K);
    char                 *e_g_req_contents = palloc(r->pool, PBC_4K);
    const char *tenc = table_get(r->headers_in, "Transfer-Encoding");
    const char *ctype = table_get(r->headers_in, "Content-type");
    const char *lenp = table_get(r->headers_in, "Content-Length");
#else
    char                 *tmp = ap_palloc(r->pool, PBC_1K);
    char                 *refresh = ap_palloc(r->pool, PBC_1K);
    char                 *pre_s = ap_palloc(r->pool, PBC_1K);
    char                 *pre_s_cookie = ap_palloc(r->pool, PBC_1K);
    char                 *g_req_cookie = ap_palloc(r->pool, PBC_4K);
    char                 *g_req_contents = ap_palloc(r->pool, PBC_4K);
    char                 *e_g_req_contents = ap_palloc(r->pool, PBC_4K);
    const char *tenc = ap_table_get(r->headers_in, "Transfer-Encoding");
    const char *ctype = ap_table_get(r->headers_in, "Content-type");
    const char *lenp = ap_table_get(r->headers_in, "Content-Length");
#endif
    char                 *host = NULL;
    char                 *args;
    char                 *refresh_e;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec    *cfg;
    request_rec          *mr = top_rrec (r);
    char                 misc_flag = '0';
    char                 *file_to_upld = NULL;
    const char           *referer;

#ifdef APACHE1_2
    cfg = (pubcookie_dir_rec *) get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                         &pubcookie_module);
#else
    cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                         &pubcookie_module);
    scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                         &pubcookie_module);
#endif

    if( cfg->super_debug )
        libpbc_debug("super-debug: auth_failed: hello\n");

    /* reset these dippy flags */
    cfg->failed = 0;

    /* deal with GET args */
    if ( r->args ) {
#ifdef APACHE1_2
        args = pcalloc (r->pool, (strlen (r->args) + 3) / 3 * 4 + 1);
#else
        args = ap_pcalloc (r->pool, (strlen (r->args) + 3) / 3 * 4 + 1);
#endif
        libpbc_base64_encode( (unsigned char *) r->args, (unsigned char *) args, strlen(r->args));
        if( cfg->super_debug ) {
            libpbc_debug("super-debug: GET args before encoding length %d, string: %s\n", strlen(r->args), r->args);
            libpbc_debug("super-debug: GET args after encoding length %d, string: %s\n", strlen(args), args);
        }
    }
    else
#ifdef APACHE1_2
        args = pstrdup(r->pool, "");
#else
        args = ap_pstrdup(r->pool, "");
#endif

    r->content_type = "text/html";

    /* if there is a non-standard port number just tack it onto the hostname  */
    /* the login server just passes it through and the redirect works         */
    if ( r->server->port != 80 )
        if ( r->server->port != 443 )
            /* because of multiple passes through don't use r->hostname() */
#ifdef APACHE1_2
            ap_snprintf(host, PBC_1K-1, "%s:%d", get_server_name(r), r->server->port);
#else
            host = ap_psprintf(r->pool, "%s:%d", ap_get_server_name(r), r->server->port);
#endif

    if ( ! host ) 
        /* because of multiple passes through on www don't use r->hostname() */
#ifdef APACHE1_2
        host = pstrdup(r->pool, get_server_name(r));
#else
        host = ap_pstrdup(r->pool, ap_get_server_name(r));
#endif

    /* To knit the referer history together */
#ifdef APACHE1_2
    referer = table_get(r->headers_in, "Referer");
#else
    referer = ap_table_get(r->headers_in, "Referer");
#endif

    /* make the granting request */
    /* the granting request is a cookie that we set  */
    /* that gets sent up to the login server cgi, it */
    /* is our main way of communicating with it      */
    ap_snprintf(g_req_contents, PBC_4K-1, 
          "%s=%s&%s=%s&%s=%c&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%d&%s=%s&%s=%s&%s=%d&%s=%c", 
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
#ifdef APACHE1_2
          get_local_host(r->pool),
#else
          ap_get_local_host(r->pool),
#endif
          PBC_GETVAR_APPSRV_ERR,
          cfg->redir_reason_no,
          PBC_GETVAR_FILE_UPLD,
          (file_to_upld ? file_to_upld : ""),
          PBC_GETVAR_REFERER,
          referer,
          PBC_GETVAR_SESSION_REAUTH,
          cfg->session_reauth,
          PBC_GETVAR_FLAG,
          misc_flag);

    if( cfg->super_debug )
        libpbc_debug("super-debug: g_req before encoding length %d, string: %s\n", strlen(g_req_contents), g_req_contents);

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

#ifdef APACHE1_2
    e_g_req_contents = palloc (r->pool, (strlen (g_req_contents) + 3) / 3 * 4);
#else
    e_g_req_contents = ap_palloc (r->pool, (strlen (g_req_contents) + 3) / 3 * 4);
#endif
#ifdef PHASEII
    libpbc_encrypt_cookie(g_req_contents, tmp, scfg->c_stuff, strlen(g_req_contents));
    libpbc_base64_encode(tmp, e_g_req_contents, strlen(g_req_contents));
#else
    libpbc_base64_encode( (unsigned char *) g_req_contents, (unsigned char *) e_g_req_contents, strlen(g_req_contents));
#endif

    /* create whole g req cookie */
#ifdef PORT80_TEST
    ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/;",
#else
    ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/; secure",
#endif
          PBC_G_REQ_COOKIENAME, 
          e_g_req_contents,
          PBC_ENTRPRS_DOMAIN);

    if( cfg->super_debug )
        libpbc_debug("super-debug: g_req length %d cookie: %s\n", strlen(g_req_cookie), g_req_cookie);

    /* make the pre-session cookie */
    pre_s = (char *) libpbc_get_cookie_p(r->pool, 
                                   (unsigned char *) "presesuser",
                                   PBC_COOKIE_TYPE_PRE_S, 
                                   PBC_CREDS_NONE, 
                                   get_pre_s_token(),
                                   (unsigned char *)appsrvid(r), 
                                   appid(r), 
                                   scfg->session_sign_ctx_plus, 
                                   scfg->c_stuff);

#ifdef APACHE1_2
#ifdef PORT80_TEST
      ap_snprintf(pre_s_cookie, PBC_1K-1, "%s=%s; domain=%s; path=%s;", 
#else
      ap_snprintf(pre_s_cookie, PBC_1K-1, "%s=%s; domain=%s; path=%s; secure", 
#endif
              PBC_PRE_S_COOKIENAME,
              pre_s, 
              get_server_name(r),
              "/");

      table_add(r->headers_out, "Set-Cookie", pre_s_cookie);
#else
#ifdef PORT80_TEST
      pre_s_cookie = ap_psprintf(r->pool, "%s=%s; domain=%s; path=%s;", 
#else
      pre_s_cookie = ap_psprintf(r->pool, "%s=%s; domain=%s; path=%s; secure", 
#endif
              PBC_PRE_S_COOKIENAME,
              pre_s, 
              ap_get_server_name(r),
              "/");

      ap_table_add(r->headers_out, "Set-Cookie", pre_s_cookie);
#endif

    /* load and send the header */
#ifdef APACHE1_2
    table_add(r->headers_out, "Set-Cookie", g_req_cookie);

    set_no_cache_headers(r);

    /* we handle multipart/form-data by setting a cookie that tells       */
    /* the login server to put up an error page.  now that we can detect  */
    /* multipart/form-data reliably it will be easier to deal with it     */
    if ( ctype && !strncmp(ctype,"multipart/form-data",strlen("multipart/form-data")) ) {

#ifdef PORT80_TEST
        ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/;",
#else
        ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/; secure",
#endif
          PBC_FORM_MP_COOKIENAME, 
          "1",
          PBC_ENTRPRS_DOMAIN);
        table_add(r->headers_out, "Set-Cookie", g_req_cookie);
        if( cfg->super_debug )
            libpbc_debug("super-debug: auth_failed: setting Form/Multipart cookie\n");
    }

    refresh_e = os_escape_path(r->pool, refresh, 0);
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
    if ( !(tenc || lenp) || r->method_number != M_POST )
        table_add(r->headers_out, "Refresh", refresh_e);
#endif
    send_http_header(r);
#else              
    ap_table_add(r->headers_out, "Set-Cookie", g_req_cookie);
  
    set_no_cache_headers(r);

    /* we handle multipart/form-data by setting a cookie that tells       */
    /* the login server to put up an error page.  now that we can detect  */
    /* multipart/form-data reliably it will be easier to deal with it     */
    if ( ctype && !strncmp(ctype,"multipart/form-data",strlen("multipart/form-data")) ) {

#ifdef PORT80_TEST
        ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/;",
#else
        ap_snprintf(g_req_cookie, PBC_4K-1, "%s=%s; domain=%s; path=/; secure",
#endif
          PBC_FORM_MP_COOKIENAME, 
          "1",
          PBC_ENTRPRS_DOMAIN);
        ap_table_add(r->headers_out, "Set-Cookie", g_req_cookie);
        if( cfg->super_debug )
            libpbc_debug("super-debug: auth_failed: setting Form/Multipart cookie\n");
    }

    refresh_e = ap_os_escape_path(r->pool, refresh, 0);
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
    if ( !(tenc || lenp) )
        ap_table_add(r->headers_out, "Refresh", refresh_e);
#endif
    ap_send_http_header(r);
#endif

    /* now deal with the body */
    if ( (ctype && strncmp(ctype,"multipart/fo",strlen("multipart/fo"))) &&
        (tenc || lenp || r->method_number == M_POST) ) {
#ifdef APACHE1_2
        rprintf(r, "%s", PBC_POST_NO_JS_HTML1);
        rprintf(r, "%s", scfg->login);
        rprintf(r, "%s", PBC_POST_NO_JS_HTML2);
        put_out_post(r);
        rprintf(r, "%s", PBC_POST_NO_JS_HTML3);
        rprintf(r, "%s", scfg->login);
        rprintf(r, "%s", PBC_WEBISO_LOGO);
        rprintf(r, "%s", PBC_POST_NO_JS_HTML4);
        rprintf(r, "%s", PBC_POST_NO_JS_BUTTON);
        rprintf(r, "%s", PBC_POST_NO_JS_HTML5);
        rprintf(r, "%s", PBC_HTML_COPYRIGHT);
        rprintf(r, "%s", PBC_POST_NO_JS_HTML6);
#else
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
        ap_rprintf(r, "%s", PBC_HTML_COPYRIGHT);
        ap_rprintf(r, "%s", PBC_POST_NO_JS_HTML6);
#endif
    }
    else {
#ifdef APACHE1_2
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
        rprintf(r, "<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
#else  
        rprintf(r, "<HTML><HEAD><meta HTTP-EQUIV=\"Refresh\" CONTENT=\"%s\"></HEAD><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n", refresh);
#endif
#else
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
        ap_rprintf(r, "<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
#else
        ap_rprintf(r, "<HTML><HEAD><meta HTTP-EQUIV=\"Refresh\" CONTENT=\"%s\"></HEAD><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n", refresh);
#endif
#endif
    }

    return OK;

}

/*                                                                            */
static int bad_user(request_rec *r) {
  r->content_type = "text/html";
#ifdef APACHE1_2
  send_http_header(r);
  rprintf(r, "Unauthorized user.");
#else
  ap_send_http_header(r);
  ap_rprintf(r, "Unauthorized user.");
#endif
  return OK;
}

/*                                                                            */
static int is_pubcookie_auth(pubcookie_dir_rec *cfg) {
  if ( cfg->creds && cfg->creds != PBC_CREDS_NONE ) {
    return TRUE;
  }
  else {
    return FALSE;
  }
}

/* figure out the session cookie name                                         */
char *make_session_cookie_name(pool *p, unsigned char *_appid)
{
  /* 
     we now use JimB style session cookie names
     session cookie names are PBC_S_COOKIENAME_appid 
   */

    char *ptr;
    char *name;

#ifdef APACHE1_2
#ifdef NO_JIMB_SESSION_NAMES
    name = pstrdup(p, PBC_S_COOKIENAME);
#else
    name = pstrcat(p, PBC_S_COOKIENAME, "_", _appid, NULL);
#endif
#else
#ifdef NO_JIMB_SESSION_NAMES
    name = ap_pstrdup(p, PBC_S_COOKIENAME);
#else
    name = ap_pstrcat(p, PBC_S_COOKIENAME, "_", _appid, NULL);
#endif
#endif

    ptr = name;
    while(*ptr) {
        if(*ptr == '/')
            *ptr = '_';
        ptr++;
    }

    return name;
}

/*                                                                            */
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
#ifdef APACHE1_2
  if( (cookie_header = table_get(mr->notes, name)) )
    return pstrdup(r->pool, cookie_header);
  if(!(cookie_header = table_get(r->headers_in, "Cookie")))
#else
  if( (cookie_header = ap_table_get(mr->notes, name)) )
    return ap_pstrdup(r->pool, cookie_header);
  if(!(cookie_header = ap_table_get(r->headers_in, "Cookie")))
#endif
    return NULL;

  /* add an equal on the end */
#ifdef APACHE1_2
  name_w_eq = pstrcat(r->pool, name, "=", NULL);
#else
  name_w_eq = ap_pstrcat(r->pool, name, "=", NULL);
#endif

  /* find the one that's pubcookie */
  if(!(cookie_header = strstr(cookie_header, name_w_eq)))
    return NULL;

  cookie_header += strlen(name_w_eq);

#ifdef APACHE1_2
  cookie = pstrdup(r->pool, cookie_header);
#else
  cookie = ap_pstrdup(r->pool, cookie_header);
#endif

  ptr = cookie;
  while(*ptr) {
    if(*ptr == ';')
      *ptr = 0;
    ptr++;
  }

  blank_cookie (r, name);
  return cookie;
}

/*                                                                            */
static void pubcookie_init(server_rec *s, pool *p) 
{
    pubcookie_server_rec *scfg;
    char *fname;
    char hostname[1024];

    gethostname(hostname, sizeof(hostname));

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config, 
                                                   &pubcookie_module);
#else
    ap_add_version_component(ap_pstrcat(p, "mod_pubcookie/", PBC_VERSION, "/", PBC_PUBID, NULL));
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config, 
                                                   &pubcookie_module);
#endif
    libpbc_config_init(NULL, "mod_pubcookie");
    libpbc_pubcookie_init();
    
    /* read and init crypt key */

    scfg->c_stuff = libpbc_init_crypt(hostname);
    if(scfg->c_stuff==0) {
        ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read init crypt file for peer '%s'",fname);
	exit(1);
    }

    /* read and init session public key */

#ifdef APACHE1_2
    fname = server_root_relative (p, 
	(scfg->s_certfile ? scfg->s_certfile : PBC_S_CERTFILE));
#else
    fname = ap_server_root_relative (p,
	(scfg->s_certfile ? scfg->s_certfile : PBC_S_CERTFILE));
#endif

    scfg->session_verf_ctx_plus = libpbc_verify_init(fname);
    if(scfg->session_verf_ctx_plus==0 ) {
        ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read session cert file '%s'",fname);
	exit(1);
    }

    /* read and init session private key */

#ifdef APACHE1_2
    fname = server_root_relative (p,
	(scfg->s_keyfile ? scfg->s_keyfile : PBC_S_KEYFILE));
#else
    fname = ap_server_root_relative (p,
	(scfg->s_keyfile ? scfg->s_keyfile : PBC_S_KEYFILE));
#endif

    scfg->session_sign_ctx_plus = libpbc_sign_init(fname);
    if(scfg->session_sign_ctx_plus==0 ) {
      	ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read session crypt file '%s'",fname);
	exit(1);
    }

    /* read and init granting public key */

#ifdef APACHE1_2
    fname = server_root_relative (p,
	(scfg->g_certfile ? scfg->g_certfile : PBC_G_CERTFILE));
#else
    fname = ap_server_root_relative (p,
	(scfg->g_certfile ? scfg->g_certfile : PBC_G_CERTFILE));
#endif

    scfg->granting_verf_ctx_plus = libpbc_verify_init(fname);
    if(scfg->granting_verf_ctx_plus==0 ) {
        ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read granting crypt file '%s'",fname);
	exit(1);
    }

}

/*                                                                            */
static void *pubcookie_server_create(pool *p, server_rec *s) {
  pubcookie_server_rec *scfg;
#ifdef APACHE1_2
  scfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
#else
  scfg = (pubcookie_server_rec *) ap_pcalloc(p, sizeof(pubcookie_server_rec));
#endif

#ifdef APACHE1_2
  scfg->login = 
	pstrcat(p, "https://", PBC_LOGIN_HOST, "/", PBC_LOGIN_URI, NULL);
#else
  scfg->login = 
	ap_pstrcat(p, "https://", PBC_LOGIN_HOST, "/", PBC_LOGIN_URI, NULL);
#endif
  scfg->dirdepth = PBC_DEFAULT_DIRDEPTH;
  scfg->authtype_names = NULL;

  return (void *)scfg;

}

/*                                                                            */
static void *pubcookie_dir_create(pool *p, char *dirspec) {
  pubcookie_dir_rec *cfg;
#ifdef APACHE1_2
  cfg = (pubcookie_dir_rec *) pcalloc(p, sizeof(pubcookie_dir_rec));
#else
  cfg = (pubcookie_dir_rec *) ap_pcalloc(p, sizeof(pubcookie_dir_rec));
#endif

  cfg->inact_exp = PBC_UNSET_INACT_EXPIRE;
  cfg->hard_exp = PBC_UNSET_HARD_EXPIRE;

  return (void *)cfg;

}

/*                                                                            */
static void *pubcookie_server_merge(pool *p, void *parent, void *newloc) {
    pubcookie_server_rec *scfg;
    pubcookie_server_rec *pscfg = (pubcookie_server_rec *)parent;
    pubcookie_server_rec *nscfg = (pubcookie_server_rec *)newloc;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
#else
    scfg = (pubcookie_server_rec *) ap_pcalloc(p, sizeof(pubcookie_server_rec));
#endif

    scfg->login = (nscfg->login == NULL) ? 
		nscfg->login : pscfg->login;
    scfg->appsrvid = (nscfg->appsrvid == NULL) ? 
		nscfg->appsrvid : pscfg->appsrvid;
    scfg->dirdepth = nscfg->dirdepth ? 
		nscfg->dirdepth : pscfg->dirdepth;
    scfg->noblank = nscfg->noblank ? 
		nscfg->noblank : pscfg->noblank;

    scfg->g_certfile = nscfg->g_certfile ? 
		nscfg->g_certfile : pscfg->g_certfile;
    scfg->s_keyfile = nscfg->s_keyfile ? 
		nscfg->s_keyfile : pscfg->s_keyfile;
    scfg->s_certfile = nscfg->s_certfile ? 
		nscfg->s_certfile : pscfg->s_certfile;
    scfg->crypt_keyfile = nscfg->crypt_keyfile ? 
		nscfg->crypt_keyfile : pscfg->crypt_keyfile;

    scfg->session_sign_ctx_plus = nscfg->session_sign_ctx_plus ? 
		nscfg->session_sign_ctx_plus : pscfg->session_sign_ctx_plus;
    scfg->session_verf_ctx_plus = nscfg->session_verf_ctx_plus ? 
		nscfg->session_verf_ctx_plus : pscfg->session_verf_ctx_plus;
    scfg->granting_verf_ctx_plus = nscfg->granting_verf_ctx_plus ? 
		nscfg->granting_verf_ctx_plus : pscfg->granting_verf_ctx_plus;
    scfg->c_stuff = nscfg->c_stuff ? 
		nscfg->c_stuff : pscfg->c_stuff;
    scfg->authtype_names = nscfg->authtype_names ? 
		nscfg->authtype_names : pscfg->authtype_names;

    return (void *)scfg;
}

/*                                                                            */
static void *pubcookie_dir_merge(pool *p, void *parent, void *newloc) {
    pubcookie_dir_rec *cfg;
    pubcookie_dir_rec *pcfg = (pubcookie_dir_rec *) parent;
    pubcookie_dir_rec *ncfg = (pubcookie_dir_rec *) newloc;

    /* cfg->failed doesn't get merged b/c is single use */
    /* cfg->has_granting doesn't get merged b/c is single use */
#ifdef APACHE1_2
    cfg = (pubcookie_dir_rec *) pcalloc(p, sizeof(pubcookie_dir_rec));
#else
    cfg = (pubcookie_dir_rec *) ap_pcalloc(p, sizeof(pubcookie_dir_rec));
#endif

    cfg->inact_exp = (ncfg->inact_exp == PBC_UNSET_INACT_EXPIRE)
			? pcfg->inact_exp : ncfg->inact_exp;
    cfg->hard_exp = (ncfg->hard_exp == PBC_UNSET_HARD_EXPIRE)
			? pcfg->hard_exp : ncfg->hard_exp;

    /* life is much easier if the default value is zero or NULL */
    cfg->appid = ncfg->appid ? 
		ncfg->appid : pcfg->appid;
    cfg->session_reauth = ncfg->session_reauth ? 
		ncfg->session_reauth : pcfg->session_reauth;
    cfg->end_session = ncfg->end_session ? 
		ncfg->end_session : pcfg->end_session;
    cfg->super_debug = ncfg->super_debug ? 
		ncfg->super_debug : pcfg->super_debug;
    return (void *) cfg;

}

/* the bestest way to deal with default values for things that go thru the    */
/* create/merge gauntlet is to wait until you're ready to use them and then   */
/* see if they've been explicitly set                                         */
void pubcookie_dir_defaults(pubcookie_dir_rec *cfg) {

    if( cfg->inact_exp == PBC_UNSET_INACT_EXPIRE )
        cfg->inact_exp = PBC_DEFAULT_INACT_EXPIRE;
    if( cfg->hard_exp == PBC_UNSET_INACT_EXPIRE )
        cfg->hard_exp = PBC_DEFAULT_INACT_EXPIRE;

}

/* when there is stuff in the server rec with non-zero defaults put them here */
void pubcookie_server_defaults(pubcookie_server_rec *scfg) {

    ;

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
#ifdef APACHE1_2
  char *new_cookie = palloc(r->pool, PBC_1K);
#else
  char *new_cookie = ap_palloc( r->pool, PBC_1K);
#endif

#ifdef APACHE1_2
  if(!auth_type(r))
    return DECLINED;

  cfg = (pubcookie_dir_rec *) get_module_config(r->per_dir_config, 
                                            &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                            &pubcookie_module);
#else
  if(!ap_auth_type(r))
    return DECLINED;

  cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                            &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                            &pubcookie_module);
#endif

  if( cfg->super_debug )
    libpbc_debug("super-debug: pubcookie_user: hello, uri: %s auth_type: %s\n", 
			r->uri, ap_auth_type(r));

  /* get defaults for unset args */
  pubcookie_dir_defaults(cfg);
  pubcookie_server_defaults(scfg);

  /* if it's basic auth then it's not pubcookie */
  if( strcasecmp(ap_auth_type(r), "basic") == 0 )
    return DECLINED;

  /* get pubcookie creds or bail if not a pubcookie auth_type */
  if( (cfg->creds = pubcookie_auth_type(r)) == PBC_CREDS_NONE )
    return DECLINED;
  
  if( cfg->super_debug )
    libpbc_debug("super-debug: pubcookie_user: going to check uri: %s creds: %c\n", r->uri, cfg->creds);

  /* maybe dump the directory and server recs */
  if( cfg->super_debug ) {
    dump_server_rec(scfg);
    dump_dir_rec(cfg);
  }

  if( cfg->super_debug )
    libpbc_debug("super-debug: pubcookie_user: about to look for some cookies; current uri: %s\n", r->uri);

  sess_cookie_name = make_session_cookie_name(p, appid(r));

  /* force SSL */
  if (ap_hook_call("ap::mod_ssl::var_lookup", &isssl, p, r->server, 
                 r->connection, r, "HTTPS") && isssl && strcmp (isssl, "on")) {
    if( cfg->super_debug )
      libpbc_debug("pubcookie_user: Not SSL; uri: %s appid: %s\n", 
                   r->uri, appid(r));
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_NOGORS_CODE;
      return OK;
  }

  /* check if the granting cookie's appid matches.  if not, then act as
     if we don't have one.  This helps if there are any old g cookies */
  cookie_data = NULL;
  if( (cookie = get_cookie(r, PBC_G_COOKIENAME)) && strcmp(cookie, "") != 0 ) {
    if( !(cookie_data = libpbc_unbundle_cookie(cookie, 
              scfg->granting_verf_ctx_plus, scfg->c_stuff)) ) {
      libpbc_debug("pubcookie_user: can't unbundle G cookie; uri: %s\n", r->uri);
      libpbc_debug("pubcookie_user: cookie is:\n%s\n", cookie);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_BADG_CODE;
      return OK;
    }
  }

  /* do we hav a session cookie for this appid? if not check the g cookie */
  if( ! cookie_data || strncasecmp( (const char *) appid(r), 
                                    (const char *) cookie_data->broken.appid, 
                                    sizeof(cookie_data->broken.appid)-1) != 0 ) {
    if( !(cookie = get_cookie(r, sess_cookie_name)) || strcmp(cookie,"") == 0 ){

      if( cfg->super_debug )
        libpbc_debug("pubcookie_user: No G or S cookie; uri: %s appid: %s sess_cookie_name: %s\n", r->uri, appid(r), sess_cookie_name);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_NOGORS_CODE;
      return OK;
    }
    else {

      if( ! (cookie_data = libpbc_unbundle_cookie(cookie, scfg->session_verf_ctx_plus, scfg->c_stuff)) ) {
        libpbc_debug("pubcookie_user: can't unbundle S cookie; uri: %s\n", r->uri);
        cfg->failed = PBC_BAD_AUTH;
        cfg->redir_reason_no = PBC_RR_BADS_CODE;
        return OK;
      }
      /* we tell everyone what authentication check we did */
#ifdef APACHE1_2
      r->connection->auth_type = pstrdup(r->pool, auth_type(r));
      r->connection->user = pstrdup(r->pool, (char *) (*cookie_data).broken.user);
#else
      r->connection->ap_auth_type = ap_pstrdup(r->pool, ap_auth_type(r));
      r->connection->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);
#endif

      if( libpbc_check_exp((*cookie_data).broken.create_ts, cfg->hard_exp) == PBC_FAIL ) {
        libpbc_debug("S cookie hard expired; user: %s cookie timestamp: %d timeout: %d now: %d uri: %s\n", 
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
          libpbc_check_exp((*cookie_data).broken.last_ts, cfg->inact_exp) == PBC_FAIL ) {
        libpbc_debug("S cookie inact expired; user: %s cookie timestamp %d timeout: %d now: %d uri: %s\n", 
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

#ifdef APACHE1_2
    /* clear granting cookie */
#ifdef PORT80_TEST
    ap_snprintf(new_cookie, PBC_1K-1, "%s=done; domain=%s; path=/; expires=%s;", 
#else
    ap_snprintf(new_cookie, PBC_1K-1, "%s=done; domain=%s; path=/; expires=%s; secure", 
#endif
       PBC_G_COOKIENAME, 
       PBC_ENTRPRS_DOMAIN, 
       EARLIEST_EVER);
    table_add(r->headers_out, "Set-Cookie", new_cookie);
#else
    /* clear granting cookie */
#ifdef PORT80_TEST
    new_cookie = ap_psprintf(r->pool, "%s=; domain=%s; path=/; expires=%s;", 
#else
    new_cookie = ap_psprintf(r->pool, "%s=; domain=%s; path=/; expires=%s; secure", 
#endif
       PBC_G_COOKIENAME, 
       PBC_ENTRPRS_DOMAIN,
       EARLIEST_EVER);
    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
#endif

#ifdef APACHE1_2
    /* clear pre session cookie */
#ifdef PORT80_TEST
    ap_snprintf(new_cookie, PBC_1K-1, "%s=done; domain=%s; path=/; expires=%s;", 
#else
    ap_snprintf(new_cookie, PBC_1K-1, "%s=done; domain=%s; path=/; expires=%s; secure", 
#endif
       PBC_PRE_S_COOKIENAME, 
       get_server_name(r), 
       EARLIEST_EVER);
    table_add(r->headers_out, "Set-Cookie", new_cookie);
#else
    /* clear pre session cookie */
#ifdef PORT80_TEST
    new_cookie = ap_psprintf(r->pool, "%s=; domain=%s; path=/; expires=%s;", 
#else
    new_cookie = ap_psprintf(r->pool, "%s=; domain=%s; path=/; expires=%s; secure", 
#endif
       PBC_PRE_S_COOKIENAME, 
       ap_get_server_name(r),
       EARLIEST_EVER);
    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
#endif

    if( cfg->super_debug )
      libpbc_debug("super-debug: pubcookie_user: has granting; current uri is: %s\n", r->uri);

    /* the granting cookie gets blanked too early and another login */
    /* server loop is required, this just speeds up that loop */
    if( strncmp(cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0 ) {
      if( cfg->super_debug )
          libpbc_debug("super-debug: pubcookie_user: in the 'speed up that loop' logic; current uri is: %s\n", r->uri);

      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_DUMMYLP_CODE;
      return OK;
    }

#ifdef APACHE1_2
    r->connection->auth_type = pstrdup(r->pool, auth_type(r));
    r->connection->user = pstrdup(r->pool, (char *) (*cookie_data).broken.user);
#else
    r->connection->ap_auth_type = ap_pstrdup(r->pool, ap_auth_type(r));
    r->connection->user = ap_pstrdup(r->pool, (char *) (*cookie_data).broken.user);
#endif

    if( libpbc_check_exp((*cookie_data).broken.create_ts, PBC_GRANTING_EXPIRE) == PBC_FAIL ) {
      libpbc_debug("pubcookie_user: G cookie expired by %ld; user: %s create: %ld uri: %s\n", time(NULL)-(*cookie_data).broken.create_ts-PBC_GRANTING_EXPIRE, (*cookie_data).broken.user, (*cookie_data).broken.create_ts, r->uri);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_GEXP_CODE;
      return OK;
    }

  }

  /* check appid */
  if( strncasecmp( (const char *) appid(r), 
                   (const char *) (*cookie_data).broken.appid, 
                   sizeof((*cookie_data).broken.appid)-1) != 0 ) {
    libpbc_debug("pubcookie_user: wrong appid; current: %s cookie: %s uri: %s\n", appid(r), (*cookie_data).broken.appid, r->uri);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGAPPID_CODE;
    return OK;
  }

  /* check appsrv id */
  if( strncasecmp( (const char *) appsrvid(r), 
                   (const char *) (*cookie_data).broken.appsrvid, 
                   sizeof((*cookie_data).broken.appsrvid)-1) != 0 ) {
    libpbc_debug("pubcookie_user: wrong app server id; current: %s cookie: %s uri: %s\n", appsrvid(r), (*cookie_data).broken.appsrvid, r->uri);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGAPPSRVID_CODE;
    return OK;
  }

  /* check version id */
  if( libpbc_check_version(cookie_data) == PBC_FAIL ) {
    libpbc_debug("pubcookie_user: wrong version id; module: %d cookie: %d uri: %s\n", PBC_VERSION, (*cookie_data).broken.version);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGVER_CODE;
    return OK;
  }

  /* check creds */
  if( cfg->creds != cookie_data->broken.creds ) {
    libpbc_debug("pubcookie_user: wrong creds; required: %c cookie: %c uri: %s\n", cfg->creds, (*cookie_data).broken.creds, r->uri);
    cfg->failed = PBC_BAD_AUTH;
    cfg->redir_reason_no = PBC_RR_WRONGCREDS_CODE;
    return OK;
  }


  if( cfg->super_debug )
    libpbc_debug("super-debug: pubcookie_user: everything is o'tay; current uri is: %s\n", r->uri);

  return OK;

}

/*                                                                            */
int pubcookie_auth (request_rec *r) {
  pubcookie_dir_rec *cfg;
  pubcookie_server_rec *scfg;

#ifdef APACHE1_2
  cfg = (pubcookie_dir_rec *)get_module_config(r->per_dir_config,
                                           &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                            &pubcookie_module);
#else
  cfg = (pubcookie_dir_rec *)ap_get_module_config(r->per_dir_config,
                                           &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                            &pubcookie_module);
#endif

  if (cfg->super_debug)
    libpbc_debug("super-debug: pubcookie_auth: hello\n");
  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;

  if(cfg->failed) {  /* pubcookie_user has failed so pass to typer */
    if (cfg->super_debug)
      libpbc_debug("super-debug: pubcookie_auth: failed with %d\n", cfg->failed);
    return OK;
  }
  return DECLINED;
}

/*                                                                            */
static int pubcookie_typer(request_rec *r) {
  pubcookie_dir_rec *cfg;
  pubcookie_server_rec *scfg;
  unsigned char *cookie;
  int first_time_in_session = 0;
#ifdef APACHE1_2
  char *new_cookie = palloc(r->pool, PBC_1K);

  if(!auth_type(r))
    return DECLINED;

  cfg = (pubcookie_dir_rec *) get_module_config(r->per_dir_config, 
                                            &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
                                            &pubcookie_module);

  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;
  if(!requires(r)) {
    log_reason("pubcookie auth configured with no requires lines", r->uri, r);
    return SERVER_ERROR;
  }

#else
  char *new_cookie = ap_palloc( r->pool, PBC_1K);

  if(!ap_auth_type(r))
    return DECLINED;

  cfg = (pubcookie_dir_rec *) ap_get_module_config(r->per_dir_config, 
                                            &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
                                            &pubcookie_module);

  if (cfg->super_debug)
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,r,"in typer, creds=0x%x",(int)cfg->creds);
  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;
  if(!ap_requires(r)) {
    ap_log_reason("pubcookie auth configured with no requires lines", r->uri, r);
    return SERVER_ERROR;
  }
#endif

  if( cfg->has_granting ) {
    if (cfg->super_debug)
      libpbc_debug("super-debug: pubcookie_typer: coming in with granting\n");
    first_time_in_session = 1;
    cfg->has_granting = 0;
  }

  /* if the inactivity timeout is turned off don't send a session cookie 
     everytime, but be sure to send a session cookie if it's the first time
     in the app
   */

  if(!cfg->failed) {
    if (cfg->super_debug)
      libpbc_debug("super-debug: pubcookie_typer: no failure\n");

    if( check_end_session(r) & PBC_END_SESSION_REDIR_MASK ) { 
      r->handler = PBC_END_SESSION_REDIR_HANDLER;
      return OK;
    }
    else if( check_end_session(r) & PBC_END_SESSION_MASK ) { 
      clear_session_cookie(r);
    }
    else if( cfg->inact_exp > 0 || first_time_in_session ) {
      set_session_cookie(r);
    }
    return DECLINED;
  } else if(cfg->failed == PBC_BAD_AUTH) {
    if (cfg->super_debug)
      libpbc_debug("super-debug: pubcookie_typer: bad auth\n");
    r->handler = PBC_AUTH_FAILED_HANDLER;
    return OK;
  } else if (cfg->failed == PBC_BAD_USER) {
    if (cfg->super_debug)
      libpbc_debug("super-debug: pubcookie_typer: bad user\n");
    r->handler = PBC_BAD_USER_HANDLER;
    return OK;
  } else {
    if (cfg->super_debug)
      libpbc_debug("super-debug: pubcookie_typer: unknown failure\n");
    return DECLINED;
  }

} /* pubcookie_typer */

/*                                                                            */
static int pubcookie_hparse(request_rec *r)
{
    char *cookies;
    char *nextcookie;

#ifdef APACHE1_2
    if (! (cookies = table_get (r->headers_in, "Cookie")))
        return OK;
    cookies = pstrdup (r->pool, cookies);
#else
    if (! (cookies = (char *)ap_table_get (r->headers_in, "Cookie")))
        return OK;
    cookies = ap_pstrdup (r->pool, cookies);
#endif
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
#ifdef APACHE1_2
        ap_snprintf(err_string, PBC_1K-1, "PUBCOOKIE: inactivity expire parameter less then allowed minimum of %d, requested %d.", PBC_MIN_INACT_EXPIRE, cfg->inact_exp);
#else
        err_string = ap_psprintf(cmd->pool, "PUBCOOKIE: inactivity expire parameter less then allowed minimum of %d, requested %d.", PBC_MIN_INACT_EXPIRE, cfg->inact_exp);
#endif
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

    return NULL;
}

/*                                                                            */
const char *pubcookie_set_appid(cmd_parms *cmd, void *mconfig, unsigned char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;
    unsigned char *c;

#ifdef APACHE1_2
    cfg->appid = palloc (cmd->pool, strlen ( (const char *) v) * 3 + 1);
#else
    cfg->appid = ap_palloc (cmd->pool, strlen ( (const char *) v) * 3 + 1);
#endif
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

/*                                                                            */
const char *pubcookie_set_appsrvid(cmd_parms *cmd, void *mconfig, unsigned char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    unsigned char *c;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                   &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);
#endif

#ifdef APACHE1_2
    scfg->appsrvid = palloc (cmd->pool, strlen ( (const char *) v) * 3 + 1);
#else
    scfg->appsrvid = ap_palloc (cmd->pool, strlen ( (const char *) v) * 3 + 1);
#endif
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

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                   &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);
#endif

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

/*                                                                            */
const char *pubcookie_set_g_certf(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                   &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);
#endif

#ifdef APACHE1_2
    scfg->g_certfile = pstrdup(cmd->pool, v);
#else
    scfg->g_certfile = ap_pstrdup(cmd->pool, v);
#endif

    return NULL;
}

/*                                                                            */
const char *pubcookie_set_s_keyf(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                   &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);
#endif

#ifdef APACHE1_2
    scfg->s_keyfile = pstrdup(cmd->pool, v);
#else
    scfg->s_keyfile = ap_pstrdup(cmd->pool, v);
#endif

    return NULL;
}

/*                                                                            */
const char *pubcookie_set_s_certf(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                   &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);
#endif

#ifdef APACHE1_2
    scfg->s_certfile = pstrdup(cmd->pool, v);
#else
    scfg->s_certfile = ap_pstrdup(cmd->pool, v);
#endif

    return NULL;
}

/*                                                                            */
const char *pubcookie_set_crypt_keyf(cmd_parms *cmd, void *mconfig, char *v) {
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;

#ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                   &pubcookie_module);
#else
    scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                   &pubcookie_module);
#endif

#ifdef APACHE1_2
    scfg->crypt_keyfile = pstrdup(cmd->pool, v);
#else
    scfg->crypt_keyfile = ap_pstrdup(cmd->pool, v);
#endif

    return NULL;
}

/*                                                                            */
const char *set_session_reauth(cmd_parms *cmd, void *mconfig, int f) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if(f != 0)
        cfg->session_reauth = PBC_SESSION_REAUTH;
    else
        cfg->session_reauth = 0;

    return NULL;
}

/* sets flag to remove session cookie                                         */
/*  can also set the action to redirecto the login server                     */
const char *set_end_session(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

#ifdef APACHE1_2
    cfg->end_session = pstrdup(cmd->pool, v);
#else
    cfg->end_session = ap_pstrdup(cmd->pool, v);
#endif

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

/*                                                                            */
const char *set_super_debug(cmd_parms *cmd, void *mconfig, int f) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if(f != 0)
        cfg->super_debug = PBC_SUPER_DEBUG;
    else
        cfg->super_debug = 0;

    return NULL;
}

/*                                                                            */
const char *pubcookie_set_no_ssl_ok(cmd_parms *cmd, void *mconfig, char *v) {
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    cfg->non_ssl_ok = 1;

    return NULL;
}

/* sets the text names for auth types                                         */
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
    {"PubCookieInactiveExpire", pubcookie_set_inact_exp, NULL, OR_OPTIONS, TAKE1,
     "Set the inactivity expire time for PubCookies."},
    {"PubCookieHardExpire", pubcookie_set_hard_exp, NULL, OR_OPTIONS, TAKE1,
     "Set the hard expire time for PubCookies."},
    {"PubCookieLogin", pubcookie_set_login, NULL, RSRC_CONF, TAKE1,
     "Set the login page for PubCookies."},
    {"PubCookieGrantingCertfile", pubcookie_set_g_certf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the certfile for Granting PubCookies."},
    {"PubCookieSessionKeyfile", pubcookie_set_s_keyf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the keyfile for Session PubCookies."},
    {"PubCookieSessionCertfile", pubcookie_set_s_certf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the certfile for Session PubCookies."},
    {"PubCookieCryptKeyfile", pubcookie_set_crypt_keyf, NULL, RSRC_CONF, TAKE1,
     "Set the name of the encryption keyfile for PubCookies."},
    {"PubCookieAppID", pubcookie_set_appid, NULL, OR_OPTIONS, TAKE1,
     "Set the name of the application."},
    {"PubCookieAppSrvID", pubcookie_set_appsrvid, NULL, RSRC_CONF, TAKE1,
     "Set the name of the server(cluster)."},
    {"PubCookieDirDepthforAppID", pubcookie_set_dirdepth, NULL, RSRC_CONF, TAKE1,
     "Specify the Directory Depth for generating default AppIDs."},
    {"PubCookieSuperDebug", set_super_debug, NULL, OR_OPTIONS, FLAG,
     "Turn on super debugging."},
    {"PubcookieSessionCauseReAuth", set_session_reauth, NULL, OR_OPTIONS, FLAG,
     "Force reauthentication for new sessions and session timeouts"},
    {"PubcookieEndSession", set_end_session, NULL, OR_OPTIONS, RAW_ARGS,
     "End application session and possibly login session"},
    {"PubCookieNoBlank", pubcookie_set_no_blank, NULL, RSRC_CONF, TAKE1,
     "Do not blank cookies."},
    {"PubCookieAuthTypeNames", set_authtype_names, NULL, RSRC_CONF, RAW_ARGS,
     "Sets the text names for authtypes."},
/* maybe for future exploration
    {"PubCookieNoSSLOK", pubcookie_set_no_ssl_ok, NULL, OR_OPTIONS, TAKE1,
     "Allow session to go non-ssl."},
*/
    {NULL}
};

/*                                                                            */
handler_rec pubcookie_handlers[] = {
    { PBC_AUTH_FAILED_HANDLER, auth_failed},
    { PBC_END_SESSION_REDIR_HANDLER, do_end_session_redirect_handler},
    { PBC_BAD_USER_HANDLER, bad_user},
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
    pubcookie_user,              /* check_user_id */
    pubcookie_auth,              /* check auth */
    NULL,                        /* check access */
    pubcookie_typer,             /* type_checker */
    NULL,                        /* fixups */
    NULL,                        /* logger */
    pubcookie_hparse             /* header parser */
};

