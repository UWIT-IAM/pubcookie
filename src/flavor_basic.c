/* the basic flavor of logins.
   expect a username and a password and checks against one of the defined
   verifiers (see 'struct verifier' and verify_*.c for possible verifiers).

   does not support multiple realms but requires the name of the local realm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "flavor.h"
#include "verify.h"

#include "pbc_config.h"

plaintext_verifier *v = NULL;
extern int debug;

static int init_basic(void)
{
    const char *vname;
    
    /* find the verifier configured */
    vname = libpbc_config_getstring("basic_verifier", NULL);

    if (!vname) {
	fprintf(stderr, "flavor_basic: no verifier configured\n");
	return -1;
    }

    v = get_verifier(vname);

    if (!v) {
	fprintf(stderr, "flavor_basic: verifier not found: %s\n", vname);
	return -1;
    }

    if (debug) {
       fprintf(stderr, "init_basic: using %s verifier\n", vname);
    }

    return 0;
}

void print_login_page(login_rec *l, login_rec *c, const char **errstr)
{
    /* currently, we never clear the login cookie
       we always clear the greq cookie */
    int need_clear_login = 0;
    int need_clear_greq = 1;
    char message_out[1024];

fprintf(stderr, "print_login_page: hello\n");
    assert(errstr);

    /* set the cookies */
    if (need_clear_login) {
	print_header("Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
		     PBC_L_COOKIENAME, 
		     PBC_CLEAR_COOKIE,
		     PBC_LOGIN_HOST,
		     LOGIN_DIR, 
		     EARLIEST_EVER);
    }

    if (need_clear_greq) {
        print_header("Set-Cookie: %s=%s; domain=%s; path=/; secure\n",
		     PBC_G_REQ_COOKIENAME, 
		     PBC_CLEAR_COOKIE,
		     PBC_ENTRPRS_DOMAIN);
    }

    /* text before the form fields */
    snprintf(message_out, sizeof(message_out), 
	     "<p>The resource you requested requires you to authenticate."
	     "  %s</p>\n", *errstr ? *errstr : "");

    tmpl_print_html(TMPL_FNAME "login_part1", 
		    "", "this reason not implemented", message_out);

    /* keep all of the state around we need */
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n", 
		PBC_GETVAR_APPSRVID, (l->appsrvid ? l->appsrvid : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_APPID, (l->appid ? l->appid : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%c\">\n", 
                "creds_from_greq", l->creds_from_greq);
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%c\">\n", 
                PBC_GETVAR_CREDS, l->creds);
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_VERSION, (l->version ? l->version : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_METHOD, (l->method ? l->method : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_HOST, (l->host ? l->host : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_URI, (l->uri ? l->uri : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_ARGS, (l->args ? l->args : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FR, (l->fr ? l->fr : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_REAL_HOST, (l->real_hostname?l->real_hostname:"") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_APPSRV_ERR, (l->appsrv_err ? l->appsrv_err : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FILE_UPLD, (l->file ? l->file : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FLAG, (l->flag ? l->flag : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_REFERER, (l->referer ? l->referer : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_POST_STUFF, (l->post_stuff ? l->post_stuff : "") );
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
		PBC_GETVAR_SESSION_REAUTH, l->session_reauth);
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		"first_kiss", (l->first_kiss ? l->first_kiss : "") );
    /* this tags the incoming request as a form reply */
    print_html("<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
		PBC_GETVAR_REPLY, FORM_REPLY);

    print_html("\n");

    /* finish off the customized login page */
    tmpl_print_html(TMPL_FNAME "login_part2", 
		    message_out,
		    "this reason not implemented");
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
static login_result process_basic(login_rec *l, login_rec *c,
				  const char **errstr)
{
    /* make sure we're initialized */
    assert(v != NULL);
    assert(l != NULL);
    /* c seems to always be null here. */
    /* XXX need to re-examine exactly what l and c should contain here */
    /* assert(c != NULL); */
    assert(errstr);

    *errstr = NULL;

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
        if (v(l->user, l->pass, NULL, l->realm, errstr) == 0) {
            if (debug) {
               fprintf(stderr, "authentication successful for %s\n", l->user);
            }

	    /* authn succeeded! */
	    
	    /* xxx modify 'l' accordingly ? */

            /* optionally stick @REALM into the username */
            if (l->user && l->realm &&
                libpbc_config_getswitch("append_realm", 0)) {
               /* append @REALM onto the username */
               char * tmp;
               tmp = calloc(strlen(l->user)+strlen(l->realm)+1, 1);
               if (tmp) {
                  strncat(tmp, l->user, strlen(l->user));
                  strncat(tmp, "@", 1);
                  strncat(tmp, l->realm, strlen(l->realm));
                  free (l->user);
                  l->user = tmp;
               }
            }


	    return LOGIN_OK;
	} else {
	    /* authn failed! */
	    if (!*errstr) {
		*errstr = "authentication failed";
	    }
	    log_message("flavor_basic: login failed: %s", *errstr);

	    /* make sure 'l' reflects that */
	    l->user = NULL;	/* in case wrong username */
	    print_login_page(l, c, errstr);
	    return LOGIN_INPROGRESS;
	}
    } else if (l->session_reauth) {
	*errstr = "reauthentication required";
	log_message("flavor_basic: %s", *errstr);

	print_login_page(l, c, errstr);
	return LOGIN_INPROGRESS;

    } else if (l->check_error) {
	*errstr = l->check_error;
	log_message("flavor_basic: %s", *errstr);

	print_login_page(l, c, errstr);
	return LOGIN_INPROGRESS;

    } else { /* valid login cookie */
	log_message("flavor_basic: free ride");
	return LOGIN_OK;
    }
}

struct login_flavor login_flavor_basic =
{
    'A', /* id */
    &init_basic, /* init_flavor() */
    &process_basic /* process_request() */
};
