/*
    $Id: mod_pubcookie.c,v 1.10 1998-10-14 19:34:19 willey Exp $
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"

#include <pem.h>
#include <time.h>
#include <sys/time.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

module pubcookie_module;

typedef struct {
  char *g_certfile;
  char *s_keyfile;
  char *s_certfile;
  char *crypt_keyfile;
  md_context_plus     *session_sign_ctx_plus;
  md_context_plus     *session_verf_ctx_plus;
  md_context_plus     *granting_verf_ctx_plus;
  crypt_stuff         *c_stuff;
  char	*appsrv_id;
} pubcookie_server_rec;

typedef struct {
  int inact_exp;
  int hard_exp;
  int failed;
  int has_granting;
  char *groupfile;
  char *login;     /* currently unused, could support different login servers */
  char *desc;      /* currently unused, could support different login servers */
  char *app_id;
  char creds;
} pubcookie_rec;

/*                                                                            */
static int auth_failed(request_rec *r) {
#ifdef APACHE1_2
  char 			*refresh = palloc(r->pool, PBC_1K);
#else
  char 			*refresh = ap_palloc(r->pool, PBC_1K);
#endif
  char			*refresh_e;
  pubcookie_server_rec 	*scfg;
  pubcookie_rec 	*cfg;

#ifdef APACHE1_2
  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
				 	 &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
	                                 &pubcookie_module);
#else
  cfg = (pubcookie_rec *) ap_get_module_config(r->per_dir_config, 
				 	 &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
	                                 &pubcookie_module);
#endif

  /* reset this dippy flag */
  cfg->failed = 0;

  r->content_type = "text/html";
  ap_snprintf(refresh, PBC_1K-1, 
	  "%d;URL=%s?one=%s&two=%s&three=%c&four=%s&five=%s&six=%s&seven=%s", 
	  PBC_REFRESH_TIME, 
	  PBC_LOGIN_PAGE, 
	  (scfg->appsrv_id ? scfg->appsrv_id : r->server->server_hostname),
	  (cfg->app_id ? cfg->app_id : r->server->server_hostname), 
	  cfg->creds, 
	  PBC_VERSION, 
	  r->method, 
	  r->server->server_hostname, 
	  r->uri);
#ifdef APACHE1_2
  refresh_e = os_escape_path(r->pool, refresh, 0);
  table_add(r->headers_out, "Refresh", refresh);
  send_http_header(r);
  rprintf(r, "<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
#else
  refresh_e = ap_os_escape_path(r->pool, refresh, 0);
  ap_table_add(r->headers_out, "Refresh", refresh);
  ap_send_http_header(r);
  ap_rprintf(r, "<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
#endif
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
static int is_pubcookie_auth(pubcookie_rec *cfg) {
  if ( cfg->creds ) {
    return TRUE;
  }
  else {
    return FALSE;
  }
}

/*                                                                            */
static int pubcookie_check_version(unsigned char *b, unsigned char *a) {
  
  if( a[0] == b[0] && a[1] == b[1] )
    return 1;
  if( a[0] == b[0] && a[1] != b[1] ) {
    libpbc_debug("Minor version mismatch cookie: %s server: %s\n", a, b);
    return 1;
  }

  return 0;

}

/*                                                                            */
static int pubcookie_check_exp(time_t fromc, int exp, int def) {

  if( (fromc + (exp ? exp : def)) > time(NULL) ) {
    return 1;
  }
  else {
    return 0;
  }
}

/*                                                                            */
static table *groups_for_user (pool *p, char *user, char *grpfile) {
    FILE *f;
#ifdef APACHE1_2
    table *grps = make_table (p, 15);
#else
    table *grps = ap_make_table (p, 15);
#endif
    pool *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

#ifdef APACHE1_2
    if(!(f=pfopen(p, grpfile, "r")))
        return NULL;

    sp = make_sub_pool (p);
    
    while(!(cfg_getline(l,MAX_STRING_LEN,f))) {
#else
    if(!(f=ap_pfopen(p, grpfile, "r")))
        return NULL;

    sp = ap_make_sub_pool (p);
    
    while(!(ap_cfg_getline(l,(size_t)MAX_STRING_LEN,(configfile_t *)f))) {
#endif
        if((l[0] == '#') || (!l[0])) continue;
        ll = l;
#ifdef APACHE1_2
        clear_pool (sp);

        group_name = getword(sp, &ll, ':');
	
        while(ll[0]) {
            w = getword_conf (sp, &ll);
            if(!strcmp(w,user)) {
                table_set (grps, group_name, "in");
                break;
            }
        }
    }
    pfclose(p, f);
    destroy_pool (sp);
    return grps;
#else
        ap_clear_pool (sp);

        group_name = ap_getword(sp, &ll, ':');

        while(ll[0]) {
            w = ap_getword_conf (sp, &ll);
            if(!strcmp(w,user)) {
                ap_table_set (grps, group_name, "in");
                break;
            }
        }
    }
    ap_pfclose(p, f);
    ap_destroy_pool (sp);
#endif
        
    return grps;
}

/*                                                                            */
char *get_cookie(request_rec *r, char *name) {
  const char *cookie_header; 
  char *cookie, *ptr;

  /* get cookies */
#ifdef APACHE1_2
  if(!(cookie_header = table_get(r->headers_in, "Cookie")))
#else
  if(!(cookie_header = ap_table_get(r->headers_in, "Cookie")))
#endif
    return NULL;

  /* find the one that's pubcookie */
  if(!(cookie_header = strstr(cookie_header, name)))
    return NULL;

  cookie_header += strlen(name);

  /* we can't assume empty cookies are 'NAME=' b/c of ie4.x */
  if ( cookie_header[0] == '=' )
      ++cookie_header;

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

  return cookie;
}

/*                                                                            */
static void pubcookie_init(server_rec *s, pool *p) {
  pubcookie_server_rec *scfg;

#ifdef APACHE1_2
  scfg = (pubcookie_server_rec *) get_module_config(s->module_config, 
						   &pubcookie_module);
#else
  scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config, 
						   &pubcookie_module);
#endif
  libpbc_pubcookie_init();

}

/*                                                                            */
static void *pubcookie_server_create(pool *p, server_rec *s) {
  pubcookie_server_rec *scfg;

#ifdef APACHE1_2
  scfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));

  scfg->appsrv_id = libpbc_alloc_init(PBC_APPSRV_ID_LEN);
//  strcpy(scfg->appsrv_id, s->server_hostname);
  strcpy(scfg->appsrv_id, get_local_host(p));
#else
  scfg = (pubcookie_server_rec *) ap_pcalloc(p, sizeof(pubcookie_server_rec));

  scfg->appsrv_id = libpbc_alloc_init(PBC_APPSRV_ID_LEN);
//  strcpy(scfg->appsrv_id, s->server_hostname);
  strcpy(scfg->appsrv_id, ap_get_local_host(p));
#endif

  scfg->c_stuff = libpbc_init_crypt(scfg->crypt_keyfile ? scfg->crypt_keyfile : PBC_CRYPT_KEYFILE);

  scfg->session_sign_ctx_plus = libpbc_sign_init(scfg->s_keyfile ? scfg->s_keyfile : PBC_S_KEYFILE);

  scfg->session_verf_ctx_plus = libpbc_verify_init(scfg->s_certfile ? scfg->s_certfile : PBC_S_CERTFILE);

  scfg->granting_verf_ctx_plus = libpbc_verify_init(scfg->g_certfile ? scfg->g_certfile : PBC_G_CERTFILE);

  return (void *) scfg;
}

/*                                                                            */
static void *pubcookie_server_merge(pool *p, void *base, void *override) {
  pubcookie_server_rec *scfg;
  pubcookie_server_rec *pcfg = (pubcookie_server_rec *) base;
  pubcookie_server_rec *ncfg = (pubcookie_server_rec *) override;

#ifdef APACHE1_2
  scfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
#else
  scfg = (pubcookie_server_rec *) ap_pcalloc(p, sizeof(pubcookie_server_rec));
#endif
  scfg->g_certfile = ncfg->g_certfile ? ncfg->g_certfile : pcfg->g_certfile;
  scfg->s_keyfile = ncfg->s_keyfile ? ncfg->s_keyfile : pcfg->s_keyfile;
  scfg->s_certfile = ncfg->s_certfile ? ncfg->s_certfile : pcfg->s_certfile;
  scfg->crypt_keyfile = ncfg->crypt_keyfile ? ncfg->crypt_keyfile : pcfg->crypt_keyfile;

  return (void *) scfg;
}

/*                                                                            */
static void *pubcookie_dir_create(pool *p, char *dirspec) {
  pubcookie_rec *cfg;
#ifdef APACHE1_2
  cfg = (pubcookie_rec *) pcalloc(p, sizeof(pubcookie_rec));
#else
  cfg = (pubcookie_rec *) ap_pcalloc(p, sizeof(pubcookie_rec));
#endif
  return (void *) cfg;
}

/*                                                                            */
static void *pubcookie_dir_merge(pool *p, void *parent, void *newloc) {
  pubcookie_rec *cfg;
  pubcookie_rec *pcfg = (pubcookie_rec *) parent;
  pubcookie_rec *ncfg = (pubcookie_rec *) newloc;

#ifdef APACHE1_2
  cfg = (pubcookie_rec *) pcalloc(p, sizeof(pubcookie_rec));
#else
  cfg = (pubcookie_rec *) ap_pcalloc(p, sizeof(pubcookie_rec));
#endif
  cfg->inact_exp = ncfg->inact_exp ? ncfg->inact_exp : pcfg->inact_exp;
  cfg->hard_exp = ncfg->hard_exp ? ncfg->hard_exp : pcfg->hard_exp;
  cfg->login = ncfg->login ? ncfg->login : pcfg->login;
  cfg->desc = ncfg->desc ? ncfg->desc : pcfg->desc;
  cfg->groupfile = ncfg->groupfile ? ncfg->groupfile : pcfg->groupfile;
  cfg->app_id = ncfg->app_id ? ncfg->app_id : pcfg->app_id;
  return (void *) cfg;
}

/*                                                                            */
static int pubcookie_user(request_rec *r) {
  pubcookie_rec *cfg;
  pubcookie_server_rec *scfg;
  char *cookie;
  pbc_cookie_data     *cookie_data;
  pool *p;

  p = r->pool;

#ifdef APACHE1_2
  if(!auth_type(r))
    return DECLINED;

  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
					    &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
	                                    &pubcookie_module);
#else
  if(!ap_auth_type(r))
    return DECLINED;

  cfg = (pubcookie_rec *) ap_get_module_config(r->per_dir_config, 
					    &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
	                                    &pubcookie_module);
#endif

  /* add creds to pubcookie record */
#ifdef APACHE1_2
  if( strcmp(auth_type(r), PBC_NUWNETID_AUTHTYPE) == 0 )
    cfg->creds = PBC_CREDS_UWNETID;
  else if( strcmp(auth_type(r), PBC_SECURID_AUTHTYPE) == 0 )
#else
  if( strcmp(ap_auth_type(r), PBC_NUWNETID_AUTHTYPE) == 0 )
    cfg->creds = PBC_CREDS_UWNETID;
  else if( strcmp(ap_auth_type(r), PBC_SECURID_AUTHTYPE) == 0 )
#endif
    cfg->creds = PBC_CREDS_SECURID;
  else {
    cfg->creds = PBC_CREDS_NONE;
    return DECLINED;
  }
  
  if( !(cookie = get_cookie(r, PBC_G_COOKIENAME)) || strcmp(cookie,"") == 0 ) {
    if( !(cookie = get_cookie(r, PBC_S_COOKIENAME)) || strcmp(cookie,"") == 0 ){
      libpbc_debug("pubcookie_user: no cookies yet, must authenticate\n");
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
    else {

      /* why reinit? */
      scfg->session_verf_ctx_plus = libpbc_verify_init(scfg->s_certfile ? scfg->s_certfile : PBC_S_CERTFILE);
      if( ! (cookie_data = libpbc_unbundle_cookie(cookie, scfg->session_verf_ctx_plus, scfg->c_stuff)) ) {
        libpbc_debug("pubcookie_user: can't unbundled session cookie: %s\n", r->uri);
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }
#ifdef APACHE1_2
      r->connection->user = pstrdup(r->pool, (*cookie_data).broken.user);
#else
      r->connection->user = ap_pstrdup(r->pool, (*cookie_data).broken.user);
#endif
      libpbc_debug("pubcookie_user: got session cookie unbundled for user %s\n", r->connection->user);

      if( ! pubcookie_check_exp((*cookie_data).broken.create_ts, 
	      cfg->hard_exp, PBC_DEFAULT_HARD_EXPIRE) ) {
        libpbc_debug("session cookie hard expired for user: %s cookie timestamp %d timeout: %d now: %d\n", (*cookie_data).broken.user, (*cookie_data).broken.create_ts, PBC_DEFAULT_HARD_EXPIRE);
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

      if( cfg->inact_exp != -1 && 
	      ! pubcookie_check_exp((*cookie_data).broken.last_ts, 
              cfg->inact_exp, PBC_DEFAULT_INACT_EXPIRE) ) {
        libpbc_debug("session cookie inact expired for user: %s cookie timestamp %d timeout: %d now: %d\n", (*cookie_data).broken.user, (*cookie_data).broken.create_ts, PBC_DEFAULT_INACT_EXPIRE);
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

    } /* end if session cookie */

  }
  else { 

    cfg->has_granting = 1;

    /* why reinit? */
    scfg->granting_verf_ctx_plus = libpbc_verify_init(scfg->g_certfile ? scfg->g_certfile : PBC_G_CERTFILE);

    if( ! (cookie_data = libpbc_unbundle_cookie(cookie, 
	      scfg->granting_verf_ctx_plus, scfg->c_stuff)) ) {
      libpbc_debug("pubcookie_user: can't unbundle granting cookie %s\n", r->uri);
      libpbc_debug("pubcookie_user: cookie is:\n%s\n", cookie);
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }

#ifdef APACHE1_2
    r->connection->user = pstrdup(r->pool, (*cookie_data).broken.user);
#else
    r->connection->user = ap_pstrdup(r->pool, (*cookie_data).broken.user);
#endif
    libpbc_debug("pubcookie_user: got session cookie unbundled for user %s\n", r->connection->user);

    if( ! pubcookie_check_exp((*cookie_data).broken.create_ts, 
	      PBC_GRANTING_EXPIRE, PBC_GRANTING_EXPIRE) ) {
      libpbc_debug("granting cookie expired for user: %s\n", (*cookie_data).broken.user);
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }

  }

  /* check app_id */
  if( strncmp((cfg->app_id?cfg->app_id:r->server->server_hostname), (*cookie_data).broken.app_id, sizeof((*cookie_data).broken.app_id)-1) != 0 ) {
    cfg->failed = PBC_BAD_AUTH;
    libpbc_debug("pubcookie_user: wrong appid; directory: %d cookie: %d\n", cfg->app_id?cfg->app_id:r->server->server_hostname, (*cookie_data).broken.app_id);
    return OK;
  }

  /* make sure this cookie is for this server */
  if( strncmp(scfg->appsrv_id, (*cookie_data).broken.appsrv_id, sizeof((*cookie_data).broken.appsrv_id)-1) != 0 ) {
    cfg->failed = PBC_BAD_AUTH;
    libpbc_debug("pubcookie_user: wrong app server id; directory: %d cookie: %d\n", scfg->appsrv_id, (*cookie_data).broken.appsrv_id);
    return OK;
  }

  if( !pubcookie_check_version((*cookie_data).broken.version, PBC_VERSION)){
    cfg->failed = PBC_BAD_AUTH;
    libpbc_debug("pubcookie_user: wrong version id; module: %d cookie: %d\n", PBC_VERSION, (*cookie_data).broken.version);
    return OK;
  }

  if( cfg->creds == PBC_CREDS_UWNETID ) {
    if( (*cookie_data).broken.creds != PBC_CREDS_UWNETID ) {
      libpbc_debug("pubcookie_user: wrong creds directory; %d cookie: %d\n", PBC_CREDS_UWNETID, (*cookie_data).broken.creds);
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
  }
  if( cfg->creds == PBC_CREDS_SECURID ) {
    if( (*cookie_data).broken.creds != PBC_CREDS_SECURID ) {
      libpbc_debug("pubcookie_user: wrong creds directory; %d cookie: %d\n", PBC_CREDS_SECURID, (*cookie_data).broken.creds);
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
  }

  return OK;

}

/*                                                                            */
int pubcookie_auth (request_rec *r) {
  pubcookie_rec *cfg;
#ifdef APACHE1_2
  const array_header *requires_struct = requires(r);
#else
  const array_header *requires_struct = ap_requires(r);
#endif
  require_line *requires_lines;
  table *grpstatus = NULL;
  int x;
  const char *line_ptr, *word_ptr;

#ifdef APACHE1_2
  cfg = (pubcookie_rec *)get_module_config(r->per_dir_config,
					   &pubcookie_module);
#else
  cfg = (pubcookie_rec *)ap_get_module_config(r->per_dir_config,
					   &pubcookie_module);
#endif

  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;

  if(cfg->failed) {  /* pubcookie_user has failed so pass to typer */
    return OK;
  }

  if (!requires_struct)
    return OK;

  if(cfg->groupfile)
    grpstatus = groups_for_user(r->pool, r->connection->user, cfg->groupfile);

  requires_lines = (require_line *)requires_struct->elts;
  for(x=0; x < requires_struct->nelts; x++) {
    line_ptr = requires_lines[x].requirement;
#ifdef APACHE1_2
    word_ptr = getword(r->pool, &line_ptr, ' ');
#else
    word_ptr = ap_getword(r->pool, &line_ptr, ' ');
#endif
    if(!strcmp(word_ptr, "valid-user"))
      return OK;
    if(!strcmp(word_ptr, "user")) {
      while(line_ptr[0]) {
#ifdef APACHE1_2
	word_ptr = getword_conf (r->pool, &line_ptr);
#else
	word_ptr = ap_getword_conf (r->pool, &line_ptr);
#endif
	if(!strcmp(r->connection->user, word_ptr))
	  return OK;
      }
    }
    if(!strcmp(word_ptr, "group")) {
      if(grpstatus) {
#ifdef APACHE1_2
	word_ptr = getword_conf(r->pool, &line_ptr);
	if(table_get(grpstatus, word_ptr))
#else
	word_ptr = ap_getword_conf(r->pool, &line_ptr);
	if(ap_table_get(grpstatus, word_ptr))
#endif
	  return OK;
      }
    }
  }

  cfg->failed = PBC_BAD_USER;
  return OK;
}

/*                                                                            */
static int pubcookie_typer(request_rec *r) {
  pubcookie_rec *cfg;
  pubcookie_server_rec *scfg;
  unsigned char	*cookie;
#ifdef APACHE1_2
  char *new_cookie = palloc( r->pool, PBC_1K);

  if(!auth_type(r))
    return DECLINED;

  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
					    &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
	                                    &pubcookie_module);

  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;

  if( cfg->has_granting ) {
    /* clear granting cookie */
    ap_snprintf(new_cookie, PBC_1K-1, "%s=; domain=%s path=/; secure", PBC_G_COOKIENAME, PBC_ENTRPRS_DOMAIN);
    table_add(r->headers_out, "Set-Cookie", new_cookie);
#else
  char *new_cookie = ap_palloc( r->pool, PBC_1K);

  if(!ap_auth_type(r))
    return DECLINED;

  cfg = (pubcookie_rec *) ap_get_module_config(r->per_dir_config, 
					    &pubcookie_module);
  scfg = (pubcookie_server_rec *) ap_get_module_config(r->server->module_config,
	                                    &pubcookie_module);

  if( !is_pubcookie_auth(cfg) ) 
    return DECLINED;

  if( cfg->has_granting ) {
    new_cookie = ap_psprintf(r->pool, "%s=; domain=%s path=/; secure", PBC_G_COOKIENAME, PBC_ENTRPRS_DOMAIN);
    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
    /* clear granting cookie */
#endif
    cfg->has_granting = 0;
  }

  if(!cfg->failed) {
    cookie = libpbc_get_cookie_p(r->pool, r->connection->user, PBC_COOKIE_TYPE_S, cfg->creds, scfg->appsrv_id, (cfg->app_id?cfg->app_id:r->server->server_hostname), scfg->session_sign_ctx_plus, scfg->c_stuff);

#ifdef APACHE1_2
    ap_snprintf(new_cookie, PBC_1K-1, "%s=%s; domain=%s path=/; secure", PBC_S_COOKIENAME, cookie, r->server->server_hostname);

    table_add(r->headers_out, "Set-Cookie", new_cookie);
#else
    new_cookie = ap_psprintf(r->pool, "%s=%s; domain=%s path=/; secure", PBC_S_COOKIENAME, cookie, r->server->server_hostname);

    ap_table_add(r->headers_out, "Set-Cookie", new_cookie);
#endif
    return DECLINED;
  } else if(cfg->failed == PBC_BAD_AUTH) {
    r->handler = PBC_AUTH_FAILED_HANDLER;
    return OK;
  } else if (cfg->failed == PBC_BAD_USER) {
    r->handler = PBC_BAD_USER_HANDLER;
    return OK;
  } else {
    return DECLINED;
  }
}

/*                                                                            */
const char *pubcookie_set_inact_exp(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;
  
  if((cfg->inact_exp = atoi(v)) <= 0 && cfg->inact_exp != -1 ) {
    return "PUBCOOKIE: Could not convert inactivity expire parameter to nonnegative number.";
  }
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_hard_exp(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;
  
  if((cfg->hard_exp = atoi(v)) <= 0) {
    return "PUBCOOKIE: Could not convert hard expire parameter to nonnegative integer.";
  }
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_login(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->login = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_desc(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->desc = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_groupfile(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->groupfile = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_app_id(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->app_id = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_g_certf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

#ifdef APACHE1_2
  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
#else
  cfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
						   &pubcookie_module);
#endif
  cfg->g_certfile = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_s_keyf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

#ifdef APACHE1_2
  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
#else
  cfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
						   &pubcookie_module);
#endif
  cfg->s_keyfile = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_s_certf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

#ifdef APACHE1_2
  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
#else
  cfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
						   &pubcookie_module);
#endif
  cfg->s_certfile = v;
  return NULL;
}

/*                                                                            */
const char *pubcookie_set_crypt_keyf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

#ifdef APACHE1_2
  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
#else
  cfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
						   &pubcookie_module);
#endif
  cfg->crypt_keyfile = v;
  return NULL;
}

/*                                                                            */
command_rec pubcookie_commands[] = {
  {"PubCookieInactiveExpire", pubcookie_set_inact_exp, NULL, OR_OPTIONS, TAKE1,
   "Set the inactivity expire time for PubCookies."},
  {"PubCookieHardExpire", pubcookie_set_hard_exp, NULL, OR_OPTIONS, TAKE1,
   "Set the hard expire time for PubCookies."},
  {"PubCookieLogin", pubcookie_set_login, NULL, OR_OPTIONS, TAKE1,
   "Set the default login page for PubCookies."},
  {"PubCookieLoginDesc", pubcookie_set_desc, NULL, OR_OPTIONS, TAKE1,
   "Set the default login description page for PubCookie."},
  {"PubCookieGroupfile", pubcookie_set_groupfile, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the PubCookie authorization group file."},
  {"PubCookieGrantingCertfile", pubcookie_set_g_certf, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the certfile for Granting PubCookies."},
  {"PubCookieSessionKeyfile", pubcookie_set_s_keyf, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the keyfile for Session PubCookies."},
  {"PubCookieSessionCertfile", pubcookie_set_s_certf, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the certfile for Session PubCookies."},
  {"PubCookieCryptKeyfile", pubcookie_set_crypt_keyf, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the encryption keyfile for PubCookies."},
  {"PubCookieAppID", pubcookie_set_app_id, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the application."},
  {NULL}
};

/*                                                                            */
handler_rec pubcookie_handlers[] = {
  { PBC_AUTH_FAILED_HANDLER, auth_failed},
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
   NULL                         /* header parser */
};

