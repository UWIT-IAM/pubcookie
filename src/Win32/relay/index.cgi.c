/* Pubcookie login relay: for myuw.net */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
/* #include <stdarg.h> */

#ifdef WIN32
# include <Windows.h>
# include <httpfilt.h>
# include "pbc_config.h"
# include "pubcookie.h"
# include "PubCookieFilter.h"
  typedef pubcookie_dir_rec pool;
#else
#include "pbc_config.h"
typedef void pool;
#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif
#endif

pool *p = NULL;

#include "pbc_configure.h"

/* See:  http://staff.washington.edu/fox/webtpl/ */
#include "webtpl.h"

/* Get a template from a path and name */

static void get_template(WebTemplate W, char *name,  char *file)
{
   char buf[MAX_PATH];
   strncpy(buf, PBC_TEMPLATES_PATH, MAX_PATH);
   strncat(buf, file, MAX_PATH - strlen(file));
   buf[MAX_PATH-1] = '\0';
   WebTemplate_get_by_name(W, name, buf);
}
   
/* Requests from an application will have a granting request
   and possibly post data.  Relay these to the login server. */
   
void relay_granting_request(WebTemplate W, char *greq)
{
   char *post;

   /* clear the granting request cookie */
   WebTemplate_set_cookie(W, PBC_G_REQ_COOKIENAME,
      "", 0, (char*)PBC_ENTRPRS_DOMAIN, "/", 1);

   get_template(W, "page", "tologin.tpl");
   WebTemplate_assign(W, "LOGIN", (char*)PBC_LOGIN_URI);
   WebTemplate_assign(W, "G_REQUEST", greq);

   if (post = WebTemplate_get_arg(W, PBC_GETVAR_POST_STUFF)) {
      WebTemplate_assign(W, "POSTSTUFF", post);
   }

   WebTemplate_assign(W, "RELAYURL", (char*)PBC_RELAY_URI);

}


/* Requests from the login server will have a granting reply
   and post data.  Relay these to the application. */


static int need_area(char *in)
{
  for (; *in; in++) {
      if (*in=='"') return (1);
      if (*in=='\n') return (1);
      if (*in=='\r') return (1);
  }
  return (0);
}

void relay_granting_reply(WebTemplate W, char *grpl)
{ 
   char *post, *url, *arg, *furl;
   time_t expire;

   get_template(W, "page", "toapp.tpl");
  
   expire = time(NULL) + PBC_GRANTING_EXPIRE;
   WebTemplate_set_cookie(W, PBC_G_COOKIENAME,
      grpl, expire, (char*)PBC_ENTRPRS_DOMAIN, "/", 1);
  
   WebTemplate_assign(W, "LOGIN", (char*)PBC_LOGIN_URI);
   /* WebTemplate_assign(W, "LOGO", "login.gif"); */
  
   /* Build the final redirection */
   url = WebTemplate_get_arg(W, "redirect_url");
   if (!url) url = "/badcall.html";
   arg = WebTemplate_html2text(WebTemplate_get_arg(W, "get_args"));

   if (arg && *arg) {
      furl = (char*) malloc(strlen(url) + strlen(arg) + 5);
      sprintf(furl, "%s?%s", url, arg);
   } else furl = strdup(url);

   WebTemplate_assign(W, "APP_URL", furl);
   free(furl);
  
   /* Look for posted data - split it into the form */
   if ((post=WebTemplate_get_arg(W, PBC_GETVAR_POST_STUFF)) && *post) {
      char *a, *v;
      char *p;
      int na;
      do {
         if (a=strchr(post, '&')) *a++ = '\0';
         if (*post) {
            if (v=strchr(post, '=')) *v++ = '\0';
            WebTemplate_assign(W, "ARGNAME", post);
            p = WebTemplate_html2text(v);
            WebTemplate_assign(W, "ARGVAL", p);
            if (need_area(p)) {
               WebTemplate_parse_dynamic(W, "page.post.area");
            } else {
               WebTemplate_parse_dynamic(W, "page.post.arg");
            }
         }
      } while (post = a);
      WebTemplate_parse_dynamic(W, "page.post");

   /* Else is a GET */
   } else WebTemplate_parse_dynamic(W, "page.get");

}



/* Logout requests from an application will have a the
   logout action variable.  Relay to the login server. */
   
void relay_logout_request(WebTemplate W, char *act)
{
   char *a1, *a2;
   char *furl;
   size_t l;

   /* clear any granting request cookie */
   WebTemplate_set_cookie(W, PBC_G_REQ_COOKIENAME,
      "", 0, (char*)PBC_ENTRPRS_DOMAIN, "/", 1);

   /* Reuse the GET redirection of the to-app template */
   get_template(W, "page", "toapp.tpl");

   /* Build the redirection */
   a1 = WebTemplate_get_arg(W, "one");
   if (!a1) a1 = "";
   a2 = WebTemplate_get_arg(W, "two");
   if (!a2) a2 = "";
   l = strlen((char*)PBC_LOGIN_URI) + 
         strlen(PBC_GETVAR_LOGOUT_ACTION) + strlen(act) +
         strlen(a1) + strlen(a2) + 32;
   furl = (char*) malloc(l);
   sprintf(furl, "%s?%s=%s&one=%s&two=%s", (char*)PBC_LOGIN_URI,
           PBC_GETVAR_LOGOUT_ACTION, act, a1, a2);

   WebTemplate_assign(W, "APP_URL", furl);
   WebTemplate_parse_dynamic(W, "page.get");
   free(furl);

}

main()
{
  WebTemplate W = newWebTemplate();
  char *req;

# ifdef WIN32
  p = (pool *)malloc(sizeof(pool));
  memset(p,0,sizeof(pool));
  strncpy(p->instance_id,PBC_RELAY_WEB_KEY,MAX_INSTANCE_ID);
# endif

  WebTemplate_set_comments(W, "#", NULL);
  WebTemplate_add_header(W, "Pragma", "No-Cache");
  WebTemplate_add_header(W, "Cache-Control",
        "no-store, no-cache, must-revalidate");
  WebTemplate_add_header(W, "Expires", "Sat, 1 Jan 2000 01:01:01 GMT");
  WebTemplate_get_args(W);

  libpbc_config_init(p, NULL, "relay");

  /* A logout request to the login server will have a
     logout action variable */

  if (req = WebTemplate_get_arg(W, PBC_GETVAR_LOGOUT_ACTION)) {
      relay_logout_request(W, req);

  /* A login reply to the application will have a granting
     cookie in posted form data */

  } else if (req = WebTemplate_get_arg(W, PBC_G_COOKIENAME)) {
      relay_granting_reply(W, req);

  /* A login request from an application will have a granting 
     request cookie */

  } else if (req = WebTemplate_get_cookie(W, PBC_G_REQ_COOKIENAME)) {
      relay_granting_request(W, req);

  /* Otherwise this is an invalid request */

  } else {
 
     get_template(W, "page", "hello.tpl");

  }

  WebTemplate_parse(W, "PAGE", "page");
  WebTemplate_write(W, "PAGE");

# ifdef WIN32
  free(p);
# endif

}
