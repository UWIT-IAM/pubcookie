/*
    $Id: pubcookie.h,v 1.3 1998-07-15 00:21:22 willey Exp $
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#define PBC_USER_LEN 42
#define PBC_VER_LEN 4
#define PBC_APPSRV_ID_LEN 20
#define PBC_APP_ID_LEN 20
#define PBC_TOT_COOKIE_DATA 96

#define PBC_BUF_LEN 4096

/* gotta start somewhere                                                      */
#define PBC_INIT_IVEC "bongo4is"
#define PBC_INIT_IVEC_LEN 8

typedef struct {
    unsigned char	user[PBC_USER_LEN];
    unsigned char	version[PBC_VER_LEN];
    unsigned char	appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char	app_id[PBC_APP_ID_LEN];
    unsigned char	type;
    unsigned char	creds;
    time_t		create_ts;
    time_t		last_ts;
} cookie_data_struct;

typedef union pbc_cookie_data_union {
    cookie_data_struct	broken;
    unsigned char      	string[PBC_TOT_COOKIE_DATA];
} pbc_cookie_data;

typedef struct {
    EVP_MD_CTX	*ctx;
    EVP_PKEY 	*private_key;
    EVP_PKEY 	*public_key;
} md_context_plus;

typedef struct {
    des_key_schedule	ks;
    des_cblock		*ivec;
    int			*num;
} crypt_stuff;

#endif /* !PUBCOOKIE_MAIN */
