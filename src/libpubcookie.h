/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: libpubcookie.h,v 1.35 2003-05-29 22:02:10 jjminer Exp $
 */

#ifndef PUBCOOKIE_LIB
#define PUBCOOKIE_LIB

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* openssl */
#ifdef OPENSSL_IN_DIR
# include <openssl/opensslv.h>
#else
# include <opensslv.h>
#endif /* OPENSSL_IN_DIR */

#if OPENSSL_VERSION_NUMBER < 0x00904000
# define PRE_OPENSSL_094
#endif

#if OPENSSL_VERSION_NUMBER == 0x0922
# define OPENSSL_0_9_2B
#endif

#include "pubcookie.h"

const char *get_my_hostname();

/** 
 * find the credential id value for an authtype name
 * @param name the name of the authtype
 * @returns either PBC_CREDS_NONE or the credential id to pass in the cookie
 */
const char libpbc_get_credential_id(pool *p, const char *name);

int libpbc_get_crypt_key(pool *p, crypt_stuff *c_stuff, const char *peer);

unsigned char *libpbc_get_cookie(pool *p, unsigned char *, 
				    unsigned char, 
				    unsigned char, 
				    int,
				    unsigned char *, 
				    unsigned char *, 
				    const char *peer);
/* for now we use the last_ts field in login cookie as expire_ts */
unsigned char *libpbc_get_cookie_with_expire(pool *p, unsigned char *, 
						unsigned char, 
						unsigned char, 
						int,
						time_t,
						unsigned char *, 
						unsigned char *, 
						const char *peer);
pbc_cookie_data *libpbc_unbundle_cookie(pool *p, char *, 
					   const char *peer);
unsigned char *libpbc_update_lastts(pool *p, pbc_cookie_data *,
				       const char *peer);
md_context_plus *libpbc_sign_init(pool *p, char *);
void libpbc_pubcookie_init(pool *p);
unsigned char *libpbc_alloc_init(pool *p, int);
unsigned char *libpbc_gethostip(pool *p);
void libpbc_free_md_context_plus(pool *p, md_context_plus *);
int libpbc_random_int(pool *p);
unsigned char *libpbc_stringify_cookie_data(pool *p, pbc_cookie_data *cookie_data); 

/**
 * generates a random key for peer and writes it to the disk
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_generate_crypt_key(pool *p, const char *peer);

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the 2048-bit key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_set_crypt_key(pool *p, const char *key, const char *peer);

char *libpbc_time_string(pool *p, time_t);
void *libpbc_abend(pool *p, const char *,...);
int libpbc_debug(pool *p, const char *,...);
void *libpbc_malloc_debug(pool *p, size_t x);
void free_debug(pool *p, void *ptr);
void libpbc_augment_rand_state(pool *p, unsigned char *, int);
char *libpbc_mod_crypt_key(pool *p, char *, unsigned char *);


int libpbc_base64_encode(pool *p, unsigned char *, unsigned char *, int );
int libpbc_base64_decode(pool *p, unsigned char *, unsigned char *, int *);
int libpbc_check_version(pool *p, pbc_cookie_data *);
int libpbc_check_exp(pool *p, time_t, int);

void libpbc_void(pool *p, void *thing);

enum {
    PBC_RR_FR_CODE =             0,
    PBC_RR_NOGORS_CODE =         1,
    PBC_RR_BADS_CODE =           2,
    PBC_RR_SHARDEX_CODE =        3,
    PBC_RR_SINAEX_CODE =         4,
    PBC_RR_DUMMYLP_CODE =        5,
    PBC_RR_BADG_CODE =           6,
    PBC_RR_GEXP_CODE =           7,
    PBC_RR_WRONGAPPID_CODE =     8,
    PBC_RR_WRONGAPPSRVID_CODE =  9,
    PBC_RR_WRONGVER_CODE =       10,
    PBC_RR_WRONGCREDS_CODE =     11,
    PBC_RR_BADPRES_CODE =        12
};

/* string translations of the above reasons */
extern const char *redirect_reason[13];

int capture_cmd_output(pool *p, char **cmd, char *out, int len);

#ifdef WIN32
#  define R_OK 4
#  define W_OK 2
#  define F_OK 0

#  define strcasecmp(a,b) _stricmp(a,b)
#  define bcopy(s, d, siz)        memcpy((d), (s), (siz))
#  define bzero(d, siz)   memset((d), '\0', (siz))
#  define snprintf _snprintf
#  define LOG_ERR 0
#  define LOG_DEBUG 1
#endif


#endif /* !PUBCOOKIE_LIB */
