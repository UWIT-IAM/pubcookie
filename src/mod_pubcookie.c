/*
    $Id: mod_pubcookie.c,v 1.2 1998-03-06 02:38:27 willey Exp $
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include <pem.h>
/* #include <envelope.h> */

#define CERTFILE "/usr/local/src/pubcookie/cookie_cert.pem"
#define SIG_LEN 128
#define COOKIENAME "pubcookie"
#define AUTH_FAILED_HANDLER "pubcookie-failed-handler"
#define BAD_USER_HANDLER "pubcookie-bad-user"
#define LOGIN_PAGE_STAT "http://www.washington.edu/login/login-stat.html"
#define LOGIN_PAGE_DYN "http://www.washington.edu/login/login-dyn.html"
#define LOGIN_DESC "http://www.washington.edu/login/login-desc.html"
#define DEFAULT_EXPIRE 1800
#define BAD_AUTH 1
#define BAD_USER 2

module pubcookie_module;

static EVP_PKEY *public_key = NULL;

typedef struct {
  char *certfile;
} pubcookie_server_rec;

typedef struct {
  int expire;
  int failed;
  char *groupfile;
  char *login;
  char *desc;
  char *cookiename;
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
	  cfg->desc ? cfg->desc : LOGIN_DESC, 
	  cfg->login ? cfg->login : LOGIN_PAGE_DYN);
  return OK;
}

static int bad_user(request_rec *r) {
  r->content_type = "text/html";
  send_http_header(r);
  rprintf(r, "Unauthorized user.");
  return OK;
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

  if(!(cookie_header = table_get(r->headers_in, "Cookie")))
    return NULL;

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

static void pubcookie_init(server_rec *s, pool*p) {
  pubcookie_server_rec *cfg;
  FILE *fp;
  X509 *x509;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config, 
						   &pubcookie_module);

  if(!(fp = pfopen(p, cfg->certfile ? cfg->certfile : CERTFILE, "r"))) {
    fprintf(stderr, "PUBCOOKIE: Could not open the certificate file.\n");
    exit(1);
  }

  if(!(x509 = (X509 *) PEM_ASN1_read((char *(*)()) d2i_X509, PEM_STRING_X509,
				     fp, NULL, NULL))) {
    fprintf(stderr, "PUBCOOKIE: Could not read the certificate file.\n");
    exit(1);
  }

  if(!(public_key = X509_extract_key(x509))) {
    fprintf(stderr, "PUBCOOKIE: Could not convert certificate to public key.\n");
    exit(1);
  }

  pfclose(p, fp);
}

static void *pubcookie_server_create(pool *p, server_rec *s) {
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
  return (void *) cfg;
}

static void *pubcookie_server_merge(pool *p, void *base, void *override) {
  pubcookie_server_rec *cfg;
  pubcookie_server_rec *pcfg = (pubcookie_server_rec *) base;
  pubcookie_server_rec *ncfg = (pubcookie_server_rec *) override;

  cfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
  cfg->certfile = ncfg->certfile ? ncfg->certfile : pcfg->certfile;

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
  cfg->expire = ncfg->expire ? ncfg->expire : pcfg->expire;
  cfg->login = ncfg->login ? ncfg->login : pcfg->login;
  cfg->desc = ncfg->desc ? ncfg->desc : pcfg->desc;
  cfg->cookiename = ncfg->cookiename ? ncfg->cookiename : pcfg->cookiename;
  cfg->groupfile = ncfg->groupfile ? ncfg->groupfile : pcfg->groupfile;
  return (void *) cfg;
}

static int pubcookie_user(request_rec *r) {
  pubcookie_rec *cfg;
  char *cookie, *decoded, *ptr;
  int cookie_time;
  EVP_MD_CTX md_ctx;

  if(!auth_type(r))
    return DECLINED;

  if(strcmp(auth_type(r), "PubCookie"))
     return DECLINED;

  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
					    &pubcookie_module);

  if(!(cookie = get_cookie(r,cfg->cookiename ? cfg->cookiename : COOKIENAME))){
    cfg->failed = BAD_AUTH;
    return OK;
  }

  decoded = pstrdup(r->pool, cookie);

  if(!base64_decode(cookie, decoded)) {
    cfg->failed = BAD_AUTH;
    return OK;
  }

  EVP_VerifyInit(&md_ctx, EVP_md5());
  EVP_VerifyUpdate(&md_ctx, decoded+SIG_LEN, strlen(decoded+SIG_LEN)); 
  if(EVP_VerifyFinal(&md_ctx, decoded, SIG_LEN, public_key) != 1) {
    cfg->failed = BAD_AUTH;
    return OK;
  }

  if(!(ptr = strchr(decoded+SIG_LEN, ':'))) {
    cfg->failed = BAD_AUTH;
    return OK;
  }

  *ptr = 0;
  ptr++;
  cookie_time = strtol(decoded + SIG_LEN, NULL, 16);

  if((cookie_time + (cfg->expire ? cfg->expire:DEFAULT_EXPIRE)) > time(NULL)) {
    r->connection->user = pstrdup(r->pool, ptr);
    return OK;
  } else {
    cfg->failed = BAD_AUTH;
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

  if(strcmp(auth_type(r), "PubCookie"))
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

  cfg->failed = BAD_USER;
  return OK;
}


static int pubcookie_typer(request_rec *r) {
  pubcookie_rec *cfg;

  cfg = (pubcookie_rec *) get_module_config(r->per_dir_config, 
					    &pubcookie_module);

  if(!cfg->failed) {
    return DECLINED;
  } else if(cfg->failed == BAD_AUTH) {
    r->handler = AUTH_FAILED_HANDLER;
    return OK;
  } else if (cfg->failed == BAD_USER) {
    r->handler = BAD_USER_HANDLER;
    return OK;
  } else {
    return DECLINED;
  }
}

const char *pubcookie_set_expire(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;
  
  if((cfg->expire = atoi(v)) <= 0) {
    return "PUBCOOKIE: Could not convert expire parameter to nonnegative integer.";
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

const char *pubcookie_set_name(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->cookiename = v;
  return NULL;
}

const char *pubcookie_set_groupfile(cmd_parms *cmd, void *mconfig, char *v) {
  pubcookie_rec *cfg = (pubcookie_rec *) mconfig;

  cfg->groupfile = v;
  return NULL;
}

const char *pubcookie_set_certfile(cmd_parms *cmd, void *mconfig, char *v) {
  server_rec *s = cmd->server;
  pubcookie_server_rec *cfg;

  cfg = (pubcookie_server_rec *) get_module_config(s->module_config,
						   &pubcookie_module);
  cfg->certfile = v;
  return NULL;
}

command_rec pubcookie_commands[] = {
  {"PubCookieExpire", pubcookie_set_expire, NULL, OR_OPTIONS, TAKE1,
   "Set the expire time for PubCookies."},
  {"PubCookieLogin", pubcookie_set_login, NULL, OR_OPTIONS, TAKE1,
   "Set the default login page for PubCookies."},
  {"PubCookieLoginDesc", pubcookie_set_desc, NULL, OR_OPTIONS, TAKE1,
   "Set the default login description page for PubCookie."},
  {"PubCookieCookiename", pubcookie_set_name, NULL, OR_OPTIONS, TAKE1,
   "Set an alternate cookie name to be used for PubCookies."},
  {"PubCookieGroupfile", pubcookie_set_groupfile, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the PubCookie authorization group file."},
  {"PubCookieCertfile", pubcookie_set_certfile, NULL, OR_OPTIONS, TAKE1,
   "Set the name of the certfile for PubCookies."},
  {NULL}
};

handler_rec pubcookie_handlers[] = {
  { AUTH_FAILED_HANDLER, auth_failed},
  { BAD_USER_HANDLER, bad_user},
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
