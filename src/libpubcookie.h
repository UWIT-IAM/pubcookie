/*
    $Id: libpubcookie.h,v 1.3 1998-07-20 10:34:34 willey Exp $
 */

#ifndef PUBCOOKIE_LIB
#define PUBCOOKIE_LIB


unsigned char *libpbc_get_cookie(char *, 
	                         unsigned char, 
				 unsigned char, 
				 unsigned char *, 
				 unsigned char *, 
				 md_context_plus *, 
				 crypt_stuff *);
pbc_cookie_data *libpbc_unbundle_cookie(char *, 
	                                md_context_plus *, 
					crypt_stuff *);
unsigned char *libpbc_update_lastts(pbc_cookie_data *,
                                    md_context_plus *, 
                                    crypt_stuff *);
int libpbc_init_cookie(pbc_cookie_data *);
void *libpbc_abend(const char *,...);
int libpbc_debug(const char *,...);
char *libpbc_time_string(time_t);
md_context_plus *libpbc_sign_init();
md_context_plus *libpbc_verify_init();
void libpbc_pubcookie_init();
void libpbc_pubcookie_exit();
void libpbc_augment_rand_state(unsigned char *, int);
crypt_stuff *libpbc_init_crypt();
char *libpbc_alloc_init(int);
char *mod_crypt_key(char *);
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

unsigned char *libpbc_sign_cookie(unsigned char *, md_context_plus *);
int libpbc_verify_sig(unsigned char *, unsigned char *, md_context_plus *);

#endif /* !PUBCOOKIE_LIB */
