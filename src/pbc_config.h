/*
    $Id: pbc_config.h,v 1.2 1998-07-15 00:21:22 willey Exp $
 */

#ifndef PUBCOOKIE_CONFIG
#define PUBCOOKIE_CONFIG

/* 
 things that came from the module
 */
#define PBC_COOKIENAME "pubcookie"
#define PBC_AUTH_FAILED_HANDLER "pubcookie-failed-handler"
#define PBC_BAD_USER_HANDLER "pubcookie-bad-user"
#define PBC_LOGIN_PAGE_STAT "http://selby.cac.washington.edu/login/login-stat.html"
#define PBC_LOGIN_PAGE_DYN "http://selby.cac.washington.edu/login/login-dyn.html"
#define PBC_LOGIN_DESC "http://selby.cac.washington.edu/login/login-desc.html"
#define PBC_CRYPT_KEYFILE "./c_key"
#define PBC_DEFAULT_EXPIRE 1800
#define PBC_BAD_AUTH 1
#define PBC_BAD_USER 2

/* 
 things that are used both places
 */
#define PBC_SIG_LEN 128
#define PBC_KEYFILE "pubcookie.key"
#define PBC_CERTFILE "pubcookie.cert"

#ifdef APACHE1_2
#define pbc_malloc(x) palloc(p, x)
#define pbc_strdup(x) pstrdup(p, x)
#define pbc_strndup(s, n) pstrdup(p, s, n)
#define pbc_fopen(x, y) pfopen(p, x, y)
#define pbc_fclose(x) fclose(p, x)
#endif

#ifndef pbc_malloc
#define pbc_malloc(x) malloc(x)
#endif
#ifndef pbc_strdup
#define pbc_strdup(x) strdup(x)
#endif
#ifndef pbc_strndup
#define pbc_strndup(s, n) (char *)strncpy(calloc(n+1, sizeof(char)), s, n)
#endif
#ifndef pbc_fopen
#define pbc_fopen(x, y) fopen(x, y)
#endif
#ifndef pbc_fclose
#define pbc_fclose(x) fclose(x)
#endif

#endif /* !PUBCOOKIE_CONFIG */
