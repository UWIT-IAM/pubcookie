/*
    $Id: libpubcookie.h,v 1.5 1998-10-14 19:34:19 willey Exp $
 */

#ifndef PUBCOOKIE_LIB
#define PUBCOOKIE_LIB


#if defined (APACHE1_2) || defined (APACHE1_3)

unsigned char *libpbc_get_cookie_p(ap_pool *, char *, 
	                         unsigned char, 
				 unsigned char, 
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
char *libpbc_alloc_init_p(pool *, int);
unsigned char *libpbc_gethostip_p(pool *);
crypt_stuff *libpbc_init_crypt_p(pool *, char *);

#else

unsigned char *libpbc_get_cookie_np(char *, 
	                         unsigned char, 
				 unsigned char, 
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
char *libpbc_alloc_init_np(int);
unsigned char *libpbc_gethostip_np();
crypt_stuff *libpbc_init_crypt_np(char *);

#endif 

char *libpbc_time_string(time_t);
void *libpbc_abend(const char *,...);
int libpbc_debug(const char *,...);
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
