/*
    $Id: mod_pubcookie.c,v 1.7 1998-07-26 06:18:22 willey Exp $
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
  char *groupfile;
  char *login;
  char *desc;
  char *app_id;
} pubcookie_rec;

static int auth_failed(request_rec *r) {
  pubcookie_rec *cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
							   &pubcookie_module);
  r->content_type = "text/html";
  send_http_header(r);
  rprintf(r, "<frameset border=no rows=\"50%%,*%%\">\n"
	  "<frame name=description src=%s>\n"
	  "<frame name=dynamic src=%s>\n"
	  "</frameset>", 
	  cfg->desc ? cfg->desc : PBC_LOGIN_DESC, 
	  cfg->login ? cfg->login : PBC_LOGIN_PAGE_DYN);
  return OK;
}

static int bad_user(request_rec *r) {
  r->content_type = "text/html";
  send_http_header(r);
  rprintf(r, "Unauthorized user.");
  return OK;
}

static int pubcookie_check_version(unsigned char *b, unsigned char *a) {
  
  if( a[0] == b[0] && a[1] == b[1] )
    return 1;
  if( a[0] == b[0] && a[1] != b[1] ) {
    libpbc_debug("Minor version mismatch cookie: %s server: %s\n", a, b);
    return 1;
  }

  return 0;

}

static int pubcookie_check_exp(time_t fromc, int exp, int def) {

  if( (fromc + (exp ? exp : def)) > time(NULL) ) {
    return OK;
  }
  else {
    return 0;
  }
}

static table *groups_for_user (pool *p, char *user, char *grpfile) {
    FILE *f;
    table *grps = make_table (p, 15);
    pool *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

    if(!(f=pfopen(p, grpfile, "r")))
        return NULL;

    sp = make_sub_pool (p);
    
    while(!(cfg_getline(l,MAX_STRING_LEN,f))) {
        if((l[0] == '#') || (!l[0])) continue;
        ll = l;
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
}

char *get_cookie(request_rec *r, char *name) {
  char *cookie_header; 
  char *cookie, *ptr;

  /* get cookies */
  if(!(cookie_header = table_get(r->headers_in, "Cookie")))
    return NULL;

  /* find the one that's pubcookie */
  if(!(cookie_header = strstr(cookie_header, name)))
    return NULL;

  cookie_header += strlen(name) + 1;

  cookie = pstrdup(r->pool, cookie_header);

  ptr = cookie;
  while(*ptr) {
    if(*ptr == ';')
      *ptr = 0;
    ptr++;
  }

  return cookie;
}

static void pubcookie_init(server_rec *s, pool *p) {
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config, 
						   &pubcookie_module);
  libpbc_pubcookie_init();

}

static void *pubcookie_server_create(pool *p, server_rec *s) {
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));

  cfg->appsrv_id = libpbc_alloc_init(PBC_APPSRV_ID_LEN);
  strcpy(cfg->appsrv_id, get_local_host(p));

  cfg->c_stuff = libpbc_init_crypt(cfg->crypt_keyfile ? cfg->crypt_keyfile : PBC_CRYPT_KEYFILE);

  cfg->session_sign_ctx_plus = libpbc_sign_init(cfg->s_keyfile ? cfg->s_keyfile : PBC_S_KEYFILE);

  cfg->session_verf_ctx_plus = libpbc_verify_init(cfg->s_certfile ? cfg->s_certfile : PBC_S_CERTFILE);

  cfg->granting_verf_ctx_plus = libpbc_verify_init(cfg->g_certfile ? cfg->g_certfile : PBC_G_CERTFILE);

  return (void *) cfg;
}

static void *pubcookie_server_merge(pool *p, void *base, void *override) {
  pubcookie_server_rec *cfg;
  pubcookie_server_rec *pcfg = (pubcookie_server_rec *) base;
  pubcookie_server_rec *ncfg = (pubcookie_server_rec *) override;

  cfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
  cfg->g_certfile = ncfg->g_certfile ? ncfg->g_certfile : pcfg->g_certfile;
  cfg->s_keyfile = ncfg->s_keyfile ? ncfg->s_keyfile : pcfg->s_keyfile;
  cfg->s_certfile = ncfg->s_certfile ? ncfg->s_certfile : pcfg->s_certfile;
  cfg->crypt_keyfile = ncfg->crypt_keyfile ? ncfg->crypt_keyfile : pcfg->crypt_keyfile;

  return (void *) cfg;
}

static void *pubcookie_dir_create(pool *p, char *dirspec) {
  pubcookie_rec *cfg;
  cfg = (pubcookie_rec *) pcalloc(p, sizeof(pubcookie_rec));
  return (void *) cfg;
}

static void *pubcookie_dir_merge(pool *p, void *parent, void *newloc) {
  pubcookie_rec *cfg;
  pubcookie_rec *pcfg = (pubcookie_rec *) parent;
  pubcookie_rec *ncfg = (pubcookie_rec *) newloc;

  cfg = (pubcookie_rec *) pcalloc(p, sizeof(pubcookie_rec));
  cfg->inact_exp = ncfg->inact_exp ? ncfg->inact_exp : pcfg->inact_exp;
  cfg->hard_exp = ncfg->hard_exp ? ncfg->hard_exp : pcfg->hard_exp;
  cfg->login = ncfg->login ? ncfg->login : pcfg->login;
  cfg->desc = ncfg->desc ? ncfg->desc : pcfg->desc;
  cfg->groupfile = ncfg->groupfile ? ncfg->groupfile : pcfg->groupfile;
  cfg->app_id = ncfg->app_id ? ncfg->app_id : pcfg->app_id;
  return (void *) cfg;
}

static int pubcookie_user(request_rec *r) {
  pubcookie_rec *cfg;
  pubcookie_server_rec *scfg;
  char *cookie, *decoded, *ptr;
  int cookie_time;
  pbc_cookie_data     *cookie_data;
  pool *p;

  p = r->pool;

  if(!auth_type(r))
    return DECLINED;

  if(strcmp(auth_type(r), PBC_NUWNETID_AUTHTYPE))
    if(strcmp(auth_type(r), PBC_SECURID_AUTHTYPE))
      return DECLINED;

  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
					    &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
	                                    &pubcookie_module);

  if(!(cookie = get_cookie(r, PBC_S_COOKIENAME))) {
    if(!(cookie = get_cookie(r, PBC_G_COOKIENAME))) {
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
    else {
      if( ! (cookie_data = libpbc_unbundle_cookie(cookie, scfg->granting_verf_ctx_plus, scfg->c_stuff)) ) {
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

      if( ! pubcookie_check_exp((*cookie_data).broken.create_ts, PBC_GRANTING_EXPIRE, PBC_GRANTING_EXPIRE) ) {
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

      /* check app_id */
      if( strcmp(cfg->app_id, (*cookie_data).broken.app_id) != 0 ) {
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

      /* make sure this cookie is for this server */
      if( strcmp(scfg->appsrv_id, (*cookie_data).broken.appsrv_id) != 0 ) {
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

      if( !pubcookie_check_version((*cookie_data).broken.version, PBC_VERSION)){
        cfg->failed = PBC_BAD_AUTH;
        return OK;
      }

    }

  }
  else {  /* we already have a session cookie */
    if( ! (cookie_data = libpbc_unbundle_cookie(cookie, scfg->session_verf_ctx_plus, scfg->c_stuff)) ) {
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
  }

  r->connection->user = pstrdup(r->pool, (*cookie_data).broken.user);
  libpbc_debug("pubcookie_user: got cookie unbundled for user %s\n", r->connection->user);

  /* check app_id */
  if( strcmp(cfg->app_id, (*cookie_data).broken.app_id) != 0 ) {
    cfg->failed = PBC_BAD_AUTH;
    return OK;
  }

  /* make sure this cookie is for this server */
  if( strcmp(scfg->appsrv_id, (*cookie_data).broken.appsrv_id) != 0 ) {
    cfg->failed = PBC_BAD_AUTH;
    return OK;
  }

  if( strcmp(auth_type(r), "PBC_NUWNETID_AUTHTYPE") == 0 ) {
    if( (*cookie_data).broken.creds != PBC_CREDS_UWNETID ) {
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
  }
  else if( strcmp(auth_type(r), "PBC_SECURID_AUTHTYPE") == 0 ) {
    if( (*cookie_data).broken.creds != PBC_CREDS_SECURID ) {
      cfg->failed = PBC_BAD_AUTH;
      return OK;
    }
  }

  if( pubcookie_check_exp((*cookie_data).broken.create_ts, cfg->hard_exp, PBC_DEFAULT_HARD_EXPIRE) &&
      ( cfg->inact_exp == -1 || pubcookie_check_exp((*cookie_data).broken.last_ts, cfg->inact_exp, PBC_DEFAULT_INACT_EXPIRE) ) ) {
    return OK;
  }
  else {
    cfg->failed = PBC_BAD_AUTH;
    return OK;
  }

}

int pubcookie_auth (request_rec *r) {
  pubcookie_rec *cfg;
  array_header *requires_struct;
  require_line *requires_lines;
  table *grpstatus = NULL;
  int x;
  const char *line_ptr, *word_ptr;

  if( strcmp(auth_type(r), PBC_NUWNETID_AUTHTYPE) != 0)
    if( strcmp(auth_type(r), PBC_SECURID_AUTHTYPE) != 0)
      return DECLINED;

  cfg = (pubcookie_rec *)get_module_config(r->per_dir_config,
					   &pubcookie_module);

  if(cfg->failed) {  /* pubcookie_user has failed so pass to typer */
    return OK;
  }

  requires_struct = requires(r);
  if (!requires_struct)
    return OK;

  if(cfg->groupfile)
    grpstatus = groups_for_user(r->pool, r->connection->user, cfg->groupfile);

  requires_lines = (require_line *)requires_struct->elts;
  for(x=0; x < requires_struct->nelts; x++) {
    line_ptr = requires_lines[x].requirement;
    word_ptr = getword(r->pool, &line_ptr, ' ');
    if(!strcmp(word_ptr, "valid-user"))
      return OK;
    if(!strcmp(word_ptr, "user")) {
      while(line_ptr[0]) {
	word_ptr = getword_conf (r->pool, &line_ptr);
	if(!strcmp(r->connection->user, word_ptr))
	  return OK;
      }
    }
    if(!strcmp(word_ptr, "group")) {
      if(grpstatus) {
	word_ptr = getword_conf(r->pool, &line_ptr);
	if(table_get(grpstatus, word_ptr))
	  return OK;
      }
    }
  }

  cfg->failed = PBC_BAD_USER;
  return OK;
}


static int pubcookie_typer(request_rec *r) {
  pubcookie_rec *cfg;
  pubcookie_server_rec *scfg;
  unsigned char	*cookie;
  char *new_cookie = palloc( r->pool, PBC_1K);

  if(!auth_type(r))
    return DECLINED;

  if(strcmp(auth_type(r), PBC_NUWNETID_AUTHTYPE))
    if(strcmp(auth_type(r), PBC_SECURID_AUTHTYPE))
      return DECLINED;

  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
					    &pubcookie_module);
  scfg = (pubcookie_server_rec *) get_module_config(r->server->module_config,
	                                    &pubcookie_module);

  /* clear granting cookie */
  ap_snprintf(new_cookie, sizeof(new_cookie), "%s=", PBC_G_COOKIENAME);
  table_add(r->headers_out, "Set-Cookie", new_cookie);

  if(!cfg->failed) {
    cookie = libpbc_get_cookie_p(r->pool, r->connection->user, 'x', 'x', scfg->appsrv_id, cfg->app_id, scfg->session_sign_ctx_plus, scfg->c_stuff);

    ap_snprintf(new_cookie, sizeof(new_cookie), "%s=%s; domain=%s path=/; secure", PBC_S_COOKIENAME, cookie, r->server->server_hostname);

    table_add(r->headers_out, "Set-Cookie", new_cookie);
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

const char *pubcookie_set_inact_exp(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;
  
  if((cfg->inact_exp = atoi(v)) <= 0 && cfg->inact_exp != -1 ) {
    return "PUBCOOKIE: Could not convert inactivity expire parameter to nonnegative number.";
  }
  return NULL;
}

const char *pubcookie_set_hard_exp(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;
  
  if((cfg->hard_exp = atoi(v)) <= 0) {
    return "PUBCOOKIE: Could not convert hard expire parameter to nonnegative integer.";
  }
  return NULL;
}

const char *pubcookie_set_login(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->login = v;
  return NULL;
}

const char *pubcookie_set_desc(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->desc = v;
  return NULL;
}

const char *pubcookie_set_groupfile(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->groupfile = v;
  return NULL;
}

const char *pubcookie_set_app_id(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->app_id = v;
  return NULL;
}

const char *pubcookie_set_g_certf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
  cfg->g_certfile = v;
  return NULL;
}

const char *pubcookie_set_s_keyf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
  cfg->s_keyfile = v;
  return NULL;
}

const char *pubcookie_set_s_certf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
  cfg->s_certfile = v;
  return NULL;
}

const char *pubcookie_set_crypt_keyf(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
  cfg->crypt_keyfile = v;
  return NULL;
}

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

handler_rec pubcookie_handlers[] = {
  { PBC_AUTH_FAILED_HANDLER, auth_failed},
  { PBC_BAD_USER_HANDLER, bad_user},
  { NULL }
};

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
