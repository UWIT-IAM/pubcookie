/*
    $Id: libpubcookie.c,v 1.1 1998-06-23 19:13:43 willey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pubcookie.h"
#include "pbc_config.h"
/*#include <envelope.h> */

/* builds, signs and returns cookie                                           */
int libpbc_get_cookie(char *user, 
	                  int type, 
			  int creds,
			  char *appsrv_id,
			  char *app_id,
			  struct context_plus ctx_plus) 
{

    pbc_cookie_data *cookie_data;

    libpbc_init_cookie(cookie_data);
    (*cookie_data).create_ts = time(NULL);
  
    /*
  memcpy(cookie_buf, buf, sig_len);
  base64_encode(cookie_buf, buf, SIG_LEN + strlen(cookie));
  printf("%s\n", buf);
  exit(0);
  */
  exit(0);
}

/* builds, signs and returns cookie                                           */
int libpbc_build_cookie(char *cookie, 
	                  char *buf, 
			  pbc_cookie_data *cookie_data,
			  EVP_PKEY *private_key,
			  EVP_MD_CTX *ctx) 
{

    (*cookie_data).create_ts = time(NULL);
  
    /*
  memcpy(cookie_buf, buf, sig_len);
  base64_encode(cookie_buf, buf, SIG_LEN + strlen(cookie));
  printf("%s\n", buf);
  exit(0);
  */
  exit(0);
}

/* mallocs and initializes a pbc_cookie_data struct                           */
int libpbc_init_cookie(pbc_cookie_data *cookie_data) 
{
    if( (cookie_data=(pbc_cookie_data *)pbc_malloc(sizeof(pbc_cookie_data))) ) {
        memset(cookie_data, 0, sizeof(cookie_data));
        return (0);
    }
    else {
        return (1);
    }
}

/*                                                                            */
int libpbc_preverify_cookie(pbc_cookie_data *cookie_data) 
{
    return (0);

}

/*                                                                            */
int libpbc_abend(pbc_cookie_data *cookie_data) 
{

    return (0);
}

/*                                                                            */
int libpbc_debug(pbc_cookie_data *cookie_data) 
{

    return (0);
}

/*                                                                            */
int libpbc_read_keyfile(FILE *key_fp, EVP_PKEY *private_key)
{
    private_key = (EVP_PKEY *)PEM_ASN1_read((char *(*)())d2i_PrivateKey, 
						  PEM_STRING_EVP_PKEY, key_fp, 
						  NULL, NULL);
    return (0);
}

/*                                                                            */
int libpbc_sign_cookie(pbc_cookie_data *cookie_data, 
	                 char *sig,
	                 int *sig_len,
			 EVP_PKEY *private_key,
                         EVP_MD_CTX *ctx) 
{

    char user[8];
    strcpy(user, "willey");
    EVP_SignUpdate(ctx, user, strlen(user));
    /*
    EVP_SignUpdate(ctx, cookie_data, sizeof(pbc_cookie_data));
     */
    if(EVP_SignFinal(ctx, sig, sig_len, private_key) != 1) {
      fprintf(stderr, "Error signing cookie.\n");
      exit(1);
    }
    exit(0);

}

/*                                                                            */
int libpbc_init_context(EVP_MD_CTX *ctx) 
{
    EVP_SignInit(ctx, EVP_md5());
    return (0);
}

