/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: pubcookie.h,v 1.20 2004-12-04 03:36:51 ryanc Exp $
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#include <security.h>

#define PBC_USER_LEN 42
#define PBC_VER_LEN 4
#define PBC_APPSRV_ID_LEN 40
#define PBC_APP_ID_LEN 128
#define PBC_TOT_COOKIE_DATA 228
#define PBC_DES_KEY_BUF 2048

#define PBC_4K 4096
#define PBC_20K 20480
#define PBC_1K 1024
#define PBC_SHORT_STRING 128
#define PBC_RAND_MALLOC_BYTES 8

#define PBC_X_STRING "XXXXXXXXXXXXX"
#define PBC_XS_IN_X_STRING 13
#define PBC_X_CHAR 'X'
#define PBC_NO_FORCE_REAUTH "NFR"
#define PBC_POST_NAME "relay.pubcookie3"

/* gotta start somewhere                                                      */
#define PBC_INIT_IVEC {0x4c,0x43,0x5f,0x98,0xbc,0xab,0xef,0xca}
#define PBC_INIT_IVEC_LEN 8
#define PBC_DES_INDEX_FOLDER 30

typedef struct {
    unsigned char	user[PBC_USER_LEN];
    unsigned char	version[PBC_VER_LEN];
    unsigned char	appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char	appid[PBC_APP_ID_LEN];
    unsigned char	type;
    unsigned char	creds;
    int			pre_sess_token;
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
    char 	key_file[600];         /*for debugging routines to print*/
} md_context_plus;

typedef struct {
    unsigned char	key_a[PBC_DES_KEY_BUF];
} crypt_stuff;

#endif /* !PUBCOOKIE_MAIN */

