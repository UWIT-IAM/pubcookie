/*
    $Id: libpubcookie.c,v 1.2 1998-06-25 03:00:58 willey Exp $
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

//char *libpbc_sign_cookie(har *cookie_string, pbc_context_plus *ctx_plus)
//{}
/*                                                                            */
//char *libpbc_sign_cookie(pbc_context_plus *ctx_plus) 
//char *libpbc_sign_cookie(char *cookie_string, pbc_context_plus *ctx_plus) 
//{
    //char	*sig;
    //int		*sig_len;
//
    //EVP_SignUpdate(ctx_plus->ctx, cookie_string, strlen(cookie_string));
    //if( EVP_SignFinal(ctx_plus->ctx, sig, sig_len, ctx_plus->private_key) )
	//return sig;
    //else
	//return NULL;
//}

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

/* mallocs and initializes a pbc_cookie_data struct                           */
pbc_cookie_data *libpbc_init_cookie_data()
{
    pbc_cookie_data *cookie_data;

    if( (cookie_data=(pbc_cookie_data *)pbc_malloc(sizeof(pbc_cookie_data))) )
        memset(cookie_data, 0, sizeof(cookie_data));
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

/* get public key and initialize verify context                               */
context_plus *libpbc_verify_init() 
{
    context_plus *ctx_plus;

    ctx_plus = libpbc_init_context_plus();
    libpbc_get_public_key(ctx_plus);
    EVP_VerifyInit(ctx_plus->ctx, EVP_md5());

    return ctx_plus;
}

/* get private key and initialize context                                     */
context_plus *libpbc_sign_init() 
{
    context_plus *ctx_plus;

    ctx_plus = libpbc_init_context_plus();
    libpbc_get_private_key(ctx_plus);
    EVP_SignInit(ctx_plus->ctx, EVP_md5());
    return ctx_plus;
}

/* check a signature after context is established                             */
int libpbc_verify_sig(char *sig, char *cookie_string, context_plus *ctx_plus)
{

    EVP_VerifyUpdate(ctx_plus->ctx, cookie_string, strlen(cookie_string));
    return EVP_VerifyFinal(ctx_plus->ctx, sig, PBC_SIG_LEN, ctx_plus->public_key);
}

/* convert cookie_data structure to a char string                             */
char *libpbc_stringify_cookie_data(pbc_cookie_data *cookie_data)
{
    char	*cookie_string;
    char	*p;
    int		len;

    len =(strlen(cookie_data->user) +
          strlen(cookie_data->version) +
          1 +					// cookie_data->type
          1 +					// cookie_data->creds
//          strlen(cookie_data->create_ts) +
//          strlen(cookie_data->last_ts) +
          strlen(cookie_data->appsrv_id) +
          strlen(cookie_data->app_id) +1) * sizeof(char);
    cookie_string = pbc_malloc( len );
    strcat(cookie_string, cookie_data->user);
    strcat(cookie_string, cookie_data->version);

    p = strchr(cookie_string, '\0');
    *p = cookie_data->type;
    *p++ = cookie_data->creds;
    *p++ = '\0';
//    strcat(cookie_string, cookie_data->create_ts);
//    strcat(cookie_string, cookie_data->last_ts);
    strcat(cookie_string, cookie_data->appsrv_id);
    strcat(cookie_string, cookie_data->app_id);

    return cookie_string;
}

/* convert a cookie char string into a cookie_data structure                  */
pbc_cookie_data *libpbc_destringify_cookie_data(char *cookie_string)
{
   
}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
char *libpbc_get_cookie(char *user, 
	                  char type, 
			  char creds,
			  char *appsrv_id,
			  char *app_id,
			  context_plus *ctx_plus) 
{

    pbc_cookie_data 	*cookie_data;
    char		*cookie_string;
    char		*cookie;
    char		*sig;

    cookie_data = libpbc_init_cookie_data();

    strncpy(cookie_data->user, user, PBC_USER_LEN);
    strncpy(cookie_data->version, PBC_VERSION, PBC_VER_LEN);
    cookie_data->type = type;
    cookie_data->creds = creds;
    cookie_data->create_ts = time(NULL);
    cookie_data->last_ts = time(NULL);
    strncpy(cookie_data->appsrv_id, appsrv_id, PBC_APPSRV_ID_LEN);
    strncpy(cookie_data->app_id, app_id, PBC_APP_ID_LEN);
  
    // make cookie string
    cookie_string = libpbc_stringify_cookie_data(cookie_data);

    // sign cookie
//    sig = libpbc_sign_cookie(cookie_string, ctx_plus);

    cookie = strcat(strcat(cookie, sig), cookie_string);

    // encrypt cookie

    return cookie;
}

/*                                                                            */
/*  deal with unbundling a cookie                                             */
/*                                                                            */
pbc_cookie_data *libpbc_unbundle_cookie(char *cookie, context_plus *ctx_plus) 
{
    pbc_cookie_data	*cookie_data;
    char		*sig;
    char		*cookie_string;

    if ( strlen(cookie) < PBC_SIG_LEN ) {
	libpbc_debug("libpbc_unbundle_cookie: cookie %s too short\n", cookie);
	return 0;
    }

    /* break cookie in two */
    sig = pbc_strndup(cookie, PBC_SIG_LEN);
    cookie_string = pbc_strndup(cookie+PBC_SIG_LEN, strlen(cookie)-PBC_SIG_LEN+1);
    // decrypt cookie

    cookie_data = libpbc_init_cookie_data();

    if( (libpbc_verify_sig(sig, cookie_string, ctx_plus)) ) {
        cookie_data = libpbc_destringify_cookie_data(cookie_string);
        return cookie_data;
    }
    else {
        return NULL;
    }


}
    
