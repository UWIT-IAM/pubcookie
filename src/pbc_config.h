/*
    $Id: pbc_config.h,v 1.1 1998-06-25 01:16:07 willey Exp $
 */

#ifndef PUBCOOKIE_CONFIG
#define PUBCOOKIE_CONFIG

/*
#define KEYFILE "/usr/local/stronghold/ssl/private/pubcookie.key"
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
