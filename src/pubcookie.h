/*
    $Id: pubcookie.h,v 1.2 1998-06-25 01:05:38 willey Exp $
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#define PBC_USER_LEN 42
#define PBC_VER_LEN 4
#define PBC_APPSRV_ID_LEN 20
#define PBC_APP_ID_LEN 10

typedef struct {
    unsigned char	user[PBC_USER_LEN];
    unsigned char	version[PBC_VER_LEN];
    unsigned char	type;
    time_t		create_ts;
    time_t		last_ts;
    unsigned char	creds;
    unsigned char	appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char	app_id[PBC_APP_ID_LEN];
} pbc_cookie_data;

typedef struct {
    EVP_MD_CTX	*ctx;
    EVP_PKEY 	*private_key;
    EVP_PKEY 	*public_key;
} context_plus;

#endif /* !PUBCOOKIE_MAIN */
