#ifndef APACHE_GLUE
#define APACHE_GLUE
/*
 * Copyright (c) 2003-06 Lars Uffmann, <lars.uffmann@telefonica.de>
 * This header file adds some glue to compile mod_pubcookie.c both
 * with apache 1.3X and 2.4X
 * 
 * Credits belong to Andreas Mueller, <andreas.mueller@othello.ch> for
 * mod_authz_ldap (http://authzldap.othello.ch/) - it was an excellent
 * example, and Alan Kennington for his documentation on porting
 * (http://www.topology.org/linux/apache.html) an Apache module to version
 * 2.X.
 *
*/

#ifdef APACHE
/* apache includes */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"

#ifdef STANDARD20_MODULE_STUFF
# define APACHE2
#else
# define APACHE1_3
#endif
#endif

#if defined(APACHE2)
# define APLOG_STATUS    0,
# define USER(r) r->user
# define AUTH_TYPE(r) r->ap_auth_type

# include "ap_config.h"
# include "apr_strings.h"
# include "apr_uri.h"

# include "apr_compat.h"
/* new interface, no compat */
#define ap_pfopen(p, f, m)	fopen(f, m)
#define ap_pfclose(p, f)	fclose(f)

/* obsolete functions: just define them */
# define ap_kill_timeout(r)
# define ap_hard_timeout(x, y)
# define ap_reset_timeout(x)
# define ap_send_http_header(r)
# define ap_log_reason(x, y, z)

# include <mod_ssl.h>

#elif defined(APACHE1_3)

typedef pool apr_pool_t;
typedef table apr_table_t;

typedef uri_components apr_uri_t;
#define apr_uri_unparse ap_unparse_uri_components
#define apr_uri_parse ap_parse_uri_components

# define APLOG_STATUS
# define USER(r) r->connection->user
# define AUTH_TYPE(r) r->connection->ap_auth_type

#define AP_INIT_FLAG(directive, function, what, where, comment)  \
        { directive, function, what, where, FLAG, comment }
#define AP_INIT_TAKE1(directive, function, what, where, comment) \
        { directive, function, what, where, TAKE1, comment }
#define AP_INIT_RAW_ARGS(directive, function, what, where, comment) \
        { directive, function, what, where, RAW_ARGS, comment }
#define AP_INIT_ITERATE(directive, function, what, where, comment) \
        { directive, function, what, where, ITERATE, comment }

extern char *ssl_var_lookup(apr_pool_t *, server_rec *, conn_rec *,
        request_rec *, char *);

# define APR_SUCCESS HTTP_OK

#else /* APACHE */

typedef void apr_pool_t;

#endif /* APACHE */
#endif
