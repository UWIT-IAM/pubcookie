/*
    $Id: pubcookie.h,v 1.1 1998-06-24 18:14:50 willey Exp $
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#define PBC_USER_LEN 42
#define PBC_VER_LEN 2
#define PBC_APPSRV_ID_LEN 20
#define PBC_APP_ID_LEN 10

typedef struct {
    char	user[PBC_USER_LEN];
    char	version[PBC_VER_LEN];
    char	type;
    time_t	create_ts;
    time_t	last_ts;
    char	creds;
    char	appsrv_id[PBC_APPSRV_ID_LEN];
    char	app_id[PBC_APP_ID_LEN];
} pbc_cookie_data;

typedef struct {
    EVP_MD_CTX	*ctx;
    EVP_PKEY 	*private_key;
} context_plus;

#endif /* !PUBCOOKIE_MAIN */
