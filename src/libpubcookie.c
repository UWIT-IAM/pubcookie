/*
    $Id: libpubcookie.c,v 1.3 1998-06-29 22:23:16 willey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include "pubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
/*#include <envelope.h> */

/* get a nice pretty log time                                                 */
static char *libpbc_time_string(time_t t)
{ 
    struct tm	*tm;
    static char	buf[128];

    tm = localtime(&t);
    strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);

    return buf;
}

/*                                                                            */
int libpbc_abend(const char *format,...)
{
    time_t	now;
    
    now = time(NULL);
    printf("%s: %s", libpbc_time_string(now), format);
    exit (1);
}

/*                                                                            */
int libpbc_debug(const char *format,...) 
{
    time_t	now;

    now = time(NULL);
    printf("%s: %s", libpbc_time_string(now), format);
    return 0;
}

unsigned char *libpbc_sign_cookie(unsigned char *cookie_string, context_plus *ctx_plus)
/*                                                                            */
{
    unsigned char	*sig;
    unsigned int	sig_len = 0;

    sig = pbc_malloc(4096);
    memset(sig, 0, sizeof(sig));

    EVP_SignUpdate(ctx_plus->ctx, cookie_string, strlen(cookie_string));
    if( EVP_SignFinal(ctx_plus->ctx, sig, &sig_len, ctx_plus->private_key) )
	return sig;
    else
	return NULL;
}

/*                                                                            */
int libpbc_get_private_key(context_plus *ctx_plus) 
{

    FILE *key_fp;

    if( ! (key_fp = pbc_fopen(PBC_KEYFILE, "r")) )
	libpbc_abend("libpbc_get_private_key: Could not open keyfile: %s\n", 
          		PBC_KEYFILE);

    if( ! (ctx_plus->private_key = 
	    		(EVP_PKEY *)PEM_ASN1_read((char *(*)())d2i_PrivateKey, 
		        PEM_STRING_EVP_PKEY, key_fp, NULL, NULL)) )
        libpbc_abend("libpbc_get_private_key: Could not read keyfile: %s\n", 
			PBC_KEYFILE);

    pbc_fclose(key_fp);
    return 1;

}

/*                                                                            */
int libpbc_get_public_key(context_plus *ctx_plus)
{
    FILE 	*fp;
    X509	*x509;

    if( ! (fp = pbc_fopen(PBC_CERTFILE, "r")) )
	libpbc_abend("libpbc_get_public_key: Could not open keyfile: %s\n", 
			PBC_CERTFILE);

    if( ! (x509 = (X509 *) PEM_ASN1_read((char *(*)())d2i_X509, 
	                PEM_STRING_X509, fp, NULL, NULL)) )
        libpbc_abend("libpbc_get_public_key: Could not read cert file: %s\n", 
			PBC_CERTFILE);

    if( ! (ctx_plus->public_key = X509_extract_key(x509)))
        libpbc_abend("libpbc_get_public_key: Could not convert cert to public key\n");

    pbc_fclose(fp);
    return 1;
}

/* mallocs a pbc_cookie_data struct                                           */
pbc_cookie_data *libpbc_init_cookie_data()
{
    pbc_cookie_data *cookie_data;

    if( ! (cookie_data=(pbc_cookie_data *)pbc_malloc(sizeof(pbc_cookie_data))) )
	libpbc_abend("libpbc_init_cookie_data: failed to allocate memory\n");

    memset(cookie_data, ' ', sizeof(pbc_cookie_data));
    return cookie_data;
}

/* init context_plus structure                                                */
context_plus *libpbc_init_context_plus()
{
    context_plus	*ctx_plus;

    if( (ctx_plus=(context_plus *)pbc_malloc(sizeof(context_plus))) &&
      (ctx_plus->ctx=(EVP_MD_CTX *)pbc_malloc(sizeof(EVP_MD_CTX))) &&
      (ctx_plus->private_key=(EVP_PKEY *)pbc_malloc(sizeof(EVP_PKEY))) ) {
        memset(ctx_plus->ctx, 0, sizeof(EVP_MD_CTX));
        memset(ctx_plus->private_key, 0, sizeof(EVP_PKEY));
    }
    else {
        libpbc_abend("libpbc_sign_init: Failed to malloc space for signing context\n");
    }

    return ctx_plus;
}

/* check a signature after context is established                             */
int libpbc_verify_sig(unsigned char *sig, unsigned char *cookie_string, context_plus *ctx_plus)
{

    EVP_VerifyUpdate(ctx_plus->ctx, cookie_string, strlen(cookie_string));
    return EVP_VerifyFinal(ctx_plus->ctx, sig, PBC_SIG_LEN, ctx_plus->public_key);
}

/*                                                                            */
/* get public key and initialize verify context                               */
/*                                                                            */
unsigned char *libpbc_stringify_cookie_data(pbc_cookie_data *cookie_data) 
{
    unsigned char	*cookie_string;
    unsigned char	*p;

    p = cookie_string = pbc_malloc(sizeof(pbc_cookie_data)+1);

//    memcpy(cookie_string, (*cookie_data).string, sizeof(pbc_cookie_data));
    memcpy(p, (*cookie_data).broken.user, PBC_USER_LEN);
    p = p + PBC_USER_LEN-1;
    *p = ' ';
    p++;
    memcpy(p, (*cookie_data).broken.version, PBC_VER_LEN));
    p = p + PBC_VER_LEN-1;
    *p = ' ';
    p++;
    cookie_string[PBC_USER_LEN+PBC_VER_LEN+PBC_APPSRV_ID_LEN-3] = ' ';
    cookie_string[PBC_USER_LEN+PBC_VER_LEN+
                  PBC_APPSRV_ID_LEN+PBC_APP_ID_LEN-4] = ' ';

    cookie_string[sizeof(pbc_cookie_data)+1] = '\0';
    return cookie_string;

}

/*                                                                            */
/* get public key and initialize verify context                               */
/*                                                                            */
context_plus *libpbc_verify_init() 
{
    context_plus *ctx_plus;

    ctx_plus = libpbc_init_context_plus();
    libpbc_get_public_key(ctx_plus);
    EVP_VerifyInit(ctx_plus->ctx, EVP_md5());

    return ctx_plus;
}

/*                                                                            */
/* get private key and initialize context                                     */
/*                                                                            */
context_plus *libpbc_sign_init() 
{
    context_plus *ctx_plus;

    ctx_plus = libpbc_init_context_plus();
    libpbc_get_private_key(ctx_plus);
    EVP_SignInit(ctx_plus->ctx, EVP_md5());
    return ctx_plus;
}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
unsigned char *libpbc_get_cookie(char *user, 
	                  unsigned char type, 
			  unsigned char creds,
			  unsigned char *appsrv_id,
			  unsigned char *app_id,
			  context_plus *ctx_plus) 
{

    pbc_cookie_data 		*cookie_data;
    unsigned char		*cookie;
    unsigned char		*cookie_string;
    unsigned char		*sig;

    cookie_data = libpbc_init_cookie_data();

    strncpy((*cookie_data).broken.user, (unsigned char *)user, PBC_USER_LEN);
    strncpy((*cookie_data).broken.version, PBC_VERSION, PBC_VER_LEN);
    (*cookie_data).broken.type = type;
    (*cookie_data).broken.creds = creds;
    (*cookie_data).broken.create_ts = time(NULL);
    (*cookie_data).broken.last_ts = time(NULL);
    strncpy((*cookie_data).broken.appsrv_id, appsrv_id, PBC_APPSRV_ID_LEN);
    strncpy((*cookie_data).broken.app_id, app_id, PBC_APP_ID_LEN);
  
    // sign cookie
    cookie_string = libpbc_stringify_cookie_data(cookie_data);

    sig = libpbc_sign_cookie(cookie_string, ctx_plus);

    cookie = pbc_malloc( (PBC_SIG_LEN+strlen((*cookie_data).string)+1) );
    cookie = (unsigned char *)strncpy(cookie, sig, PBC_SIG_LEN);
    cookie = (unsigned char *)strcat(cookie, (*cookie_data).string);

    // encrypt cookie

    return cookie;
}

/*                                                                            */
/*  deal with unbundling a cookie                                             */
/*                                                                            */
pbc_cookie_data *libpbc_unbundle_cookie(char *cookie, context_plus *ctx_plus) 
{
    pbc_cookie_data	*cookie_data;
    unsigned char		*sig;
    unsigned char		*cookie_string;

    if ( strlen(cookie) < (PBC_SIG_LEN) ) {
	libpbc_debug("libpbc_unbundle_cookie: cookie %s too short\n", cookie);
	return 0;
    }

    /* break cookie in two */
    sig = (unsigned char *)pbc_strndup(cookie, PBC_SIG_LEN);
    cookie_string = (unsigned char *)pbc_strndup(cookie+PBC_SIG_LEN, strlen(cookie)-PBC_SIG_LEN+1);
    // decrypt cookie

    cookie_data = libpbc_init_cookie_data();

    if( (libpbc_verify_sig(sig, cookie_string, ctx_plus)) ) {
        strcpy((*cookie_data).string, cookie_string);
        return cookie_data;
    }
    else {
        return NULL;
    }


}
    
/*                                                                            */
/*  update last_ts in cookie                                                  */
/*                                                                            */
unsigned char *libpbc_update_lastts(char *cookie, context_plus *ctx_plus) 
{
    pbc_cookie_data	*cookie_data;
    unsigned char	*sig;
    unsigned char	*cookie_string;

    if ( strlen(cookie) < (PBC_SIG_LEN) ) {
	libpbc_debug("libpbc_unbundle_cookie: cookie %s too short\n", cookie);
	return 0;
    }

    // decrypt cookie

    /* break cookie in two */
    sig = (unsigned char *)pbc_strndup(cookie, PBC_SIG_LEN);
    cookie_string = (unsigned char *)pbc_strndup(cookie+PBC_SIG_LEN, strlen(cookie)-PBC_SIG_LEN+1);

    cookie_data = libpbc_init_cookie_data();

    if( (libpbc_verify_sig(sig, cookie_string, ctx_plus)) ) {
        strcpy((*cookie_data).string, cookie_string);
    }
    else {
        return cookie_string;
    }

    return cookie_string;

}
    
