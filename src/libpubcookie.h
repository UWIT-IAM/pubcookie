
/* Copyright 1999, University of Washington.  All rights reserved. */

/*
    $Id: libpubcookie.h,v 1.10 1999-08-11 23:00:39 willey Exp $
 */

#ifndef PUBCOOKIE_LIB
#define PUBCOOKIE_LIB


#ifdef APACHE1_2


unsigned char *libpbc_get_cookie_p(pool *, unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
				 unsigned char *, 
				 unsigned char *, 
				 md_context_plus *, 
				 crypt_stuff *);
pbc_cookie_data *libpbc_unbundle_cookie_p(pool *, char *, 
	                                md_context_plus *, 
					crypt_stuff *);
unsigned char *libpbc_update_lastts_p(pool *, pbc_cookie_data *,
                                    md_context_plus *, 
                                    crypt_stuff *);
md_context_plus *libpbc_sign_init_p(pool *, char *);
md_context_plus *libpbc_verify_init_p(pool *, char *);
void libpbc_pubcookie_init_p(pool *);
void libpbc_pubcookie_exit_p(pool *);
unsigned char *libpbc_alloc_init_p(pool *, int);
unsigned char *libpbc_gethostip_p(pool *);
crypt_stuff *libpbc_init_crypt_p(pool *, char *);
void libpbc_free_md_context_plus_p(pool *, md_context_plus *);
void libpbc_free_crypt_p(pool *, crypt_stuff *);

#else
#ifdef APACHE1_3

unsigned char *libpbc_get_cookie_p(ap_pool *, unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
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
void libpbc_pubcookie_exit_p(ap_pool *);
unsigned char *libpbc_alloc_init_p(ap_pool *, int);
unsigned char *libpbc_gethostip_p(ap_pool *);
crypt_stuff *libpbc_init_crypt_p(ap_pool *, char *);
void libpbc_free_md_context_plus_p(ap_pool *, md_context_plus *);
void libpbc_free_crypt_p(ap_pool *, crypt_stuff *);

#else

unsigned char *libpbc_get_cookie_np(unsigned char *, 
	                         unsigned char, 
				 unsigned char, 
				 int,
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
void libpbc_pubcookie_exit_np();
unsigned char *libpbc_alloc_init_np(int);
unsigned char *libpbc_gethostip_np();
crypt_stuff *libpbc_init_crypt_np(char *);
void libpbc_free_md_context_plus_np(md_context_plus *);
void libpbc_free_crypt_np(crypt_stuff *);

#endif 
#endif

char *libpbc_time_string(time_t);
void *libpbc_abend(const char *,...);
int libpbc_debug(const char *,...);
void *malloc_debug(size_t x);
void free_debug(void *p);
void libpbc_augment_rand_state(unsigned char *, int);
char *libpbc_mod_crypt_key(char *, unsigned char *);
int libpbc_encrypt_cookie(unsigned char *, 
	                  unsigned char *, 
                          crypt_stuff *, 
                          long);
int libpbc_decrypt_cookie(unsigned char *, 
	                  unsigned char *, 
                          crypt_stuff *,
	     	          long);
int base64_encode(unsigned char *in, unsigned char *out, int size);
int base64_decode(unsigned char *in, unsigned char *out);

#endif /* !PUBCOOKIE_LIB */
