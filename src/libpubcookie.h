/*
    $Id: libpubcookie.h,v 1.2 1998-07-15 00:21:22 willey Exp $
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
int libpbc_init_cookie(pbc_cookie_data *);
void *libpbc_abend(const char *,...);
int libpbc_debug(const char *,...);
md_context_plus *libpbc_sign_init();
md_context_plus *libpbc_verify_init();
crypt_stuff *libpbc_init_crypt();
void libpbc_encrypt_cookie(unsigned char *, 
	                   unsigned char *, 
                           crypt_stuff *, 
                           long);
void libpbc_decrypt_cookie(unsigned char *, 
	                   unsigned char *, 
                           crypt_stuff *,
			   long);
int base64_encode(unsigned char *in, unsigned char *out, int size);
int base64_decode(unsigned char *in, unsigned char *out);

unsigned char *libpbc_sign_cookie(unsigned char *, md_context_plus *);
int libpbc_verify_sig(unsigned char *, unsigned char *, md_context_plus *);

#endif /* !PUBCOOKIE_LIB */
