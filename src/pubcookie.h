/*
    $Id: pubcookie.h,v 1.4 1998-07-20 10:34:34 willey Exp $
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#define PBC_USER_LEN 42
#define PBC_VER_LEN 4
#define PBC_APPSRV_ID_LEN 20
#define PBC_APP_ID_LEN 20
#define PBC_TOT_COOKIE_DATA 96
#define PBC_DES_KEY_BUF 2048

#define PBC_4K 4096
#define PBC_1K 1024
#define PBC_RAND_MALLOC_BYTES 8

/* gotta start somewhere                                                      */
#define PBC_INIT_IVEC {0x4c,0x43,0x5f,0x98,0xbc,0xab,0xef,0xca}
#define PBC_INIT_IVEC_LEN 8
#define PBC_DES_INDEX_FOLDER 30

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
    unsigned char	key_a[PBC_DES_KEY_BUF];
} crypt_stuff;

#endif /* !PUBCOOKIE_MAIN */
