/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is the header file for the pubcookie library, things
    in here are only used by the library.

    logic for how the pubcookie include files are devided up:
       libpubcookie.h: only stuff used in library
       pubcookie.h: stuff used in the module and library
       pbc_config.h: stuff used in the module and library that 
            people might want to change, as far a local configuration
       pbc_version.h: only version stuff

 */

/*
    $Id: libpubcookie.h,v 1.19 2002-06-13 17:41:39 jteaton Exp $
 */

#ifndef PUBCOOKIE_LIB
#define PUBCOOKIE_LIB

#include <opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x00904000
#define PRE_OPENSSL_094
#endif
#if OPENSSL_VERSION_NUMBER == 0x0922
#define OPENSSL_0_9_2B
#endif

#include "pubcookie.h"

char *get_my_hostname();

#ifdef APACHE1_3
int libpbc_get_crypt_key_p(pool *p, crypt_stuff *c_stuff, char *peer);

unsigned char *libpbc_get_cookie_p(ap_pool *, unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
				 unsigned char *, 
				 unsigned char *, 
				 md_context_plus *, 
				 crypt_stuff *);
/* for now we use the last_ts field in login cookie as expire_ts */
unsigned char *libpbc_get_cookie_with_expire_p(ap_pool *, unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
				 time_t,
				 unsigned char *, 
				 unsigned char *, 
				 md_context_plus *, 
				 crypt_stuff *);
pbc_cookie_data *libpbc_unbundle_cookie_p(ap_pool *, char *, 
	                                md_context_plus *, 
					crypt_stuff *);
unsigned char *libpbc_update_lastts_p(ap_pool *, pbc_cookie_data *,
                                    md_context_plus *, 
                                    crypt_stuff *);
md_context_plus *libpbc_sign_init_p(ap_pool *, char *);
md_context_plus *libpbc_verify_init_p(ap_pool *, char *);
void libpbc_pubcookie_init_p(ap_pool *);
unsigned char *libpbc_alloc_init_p(ap_pool *, int);
unsigned char *libpbc_gethostip_p(ap_pool *);
crypt_stuff *libpbc_init_crypt_p(ap_pool *, char *);
void libpbc_free_md_context_plus_p(ap_pool *, md_context_plus *);
void libpbc_free_crypt_p(ap_pool *, crypt_stuff *);

#else
int libpbc_get_crypt_key_np(crypt_stuff *c_stuff, char *peer);

unsigned char *libpbc_get_cookie_np(unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
				 unsigned char *, 
				 unsigned char *, 
				 md_context_plus *, 
				 crypt_stuff *);
/* for now we use the last_ts field in login cookie as expire_ts */
unsigned char *libpbc_get_cookie_with_expire_np(unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
				 time_t,
				 unsigned char *, 
				 unsigned char *, 
				 md_context_plus *, 
				 crypt_stuff *);
pbc_cookie_data *libpbc_unbundle_cookie_np(char *, 
	                                md_context_plus *, 
					crypt_stuff *);
unsigned char *libpbc_update_lastts_np(pbc_cookie_data *,
                                    md_context_plus *, 
                                    crypt_stuff *);
md_context_plus *libpbc_sign_init_np(char *);
md_context_plus *libpbc_verify_init_np(char *);
void libpbc_pubcookie_init_np();
unsigned char *libpbc_alloc_init_np(int);
unsigned char *libpbc_gethostip_np();
crypt_stuff *libpbc_init_crypt_np(char *);
void libpbc_free_md_context_plus_np(md_context_plus *);
void libpbc_free_crypt_np(crypt_stuff *);

#endif

char *libpbc_time_string(time_t);
void *libpbc_abend(const char *,...);
int libpbc_debug(const char *,...);
void *malloc_debug(size_t x);
void free_debug(void *p);
void libpbc_augment_rand_state(unsigned char *, int);
char *libpbc_mod_crypt_key(char *, unsigned char *);

/**
 * generates a random key for peer and writes it to the disk
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_generate_crypt_key(const char *peer);

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the 2048-bit key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_set_crypt_key(const char *key, const char *peer);

int libpbc_encrypt_cookie(unsigned char *, 
	                  unsigned char *, 
                          crypt_stuff *, 
                          long);
int libpbc_decrypt_cookie(unsigned char *, 
	                  unsigned char *, 
                          crypt_stuff *,
	     	          long);
int libpbc_base64_encode(unsigned char *, unsigned char *, int );
int libpbc_base64_decode(unsigned char *, unsigned char *);
int libpbc_check_version(pbc_cookie_data *);
int libpbc_check_exp(time_t, int);

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
    PBC_RR_WRONGCREDS_CODE =     11
};

/* string translations of the above reasons */
extern const char *redirect_reason[12];

#endif /* !PUBCOOKIE_LIB */
