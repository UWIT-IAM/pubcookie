/*
    $Id: libpubcookie.c,v 1.5 1998-07-17 04:29:16 willey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
/* ssleay lib stuff */
#include <pem.h>
#include <des.h>
#include <rand.h>
#include <err.h>
/* pubcookie lib stuff */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
/*#include <envelope.h> */

/* get a nice pretty log time                                                 */
char *libpbc_time_string(time_t t)
{ 
    struct tm	*tm;
    static char	buf[128];

    tm = localtime(&t);
    strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);

    return buf;
}

/* when things fail too bandly to go on ...                                   */
void *libpbc_abend(const char *format,...)
{
    time_t	now;
    va_list	args;
    char	format_w_time[1024];
    
    va_start(args, format);
    now = time(NULL);
    sprintf(format_w_time, "%s: ABEND: %s", libpbc_time_string(now), format);
    vprintf(format_w_time, args);
    va_end(args);
    exit (EXIT_FAILURE);
}

/* get some dubgging into to stdout                                           */
int libpbc_debug(const char *format,...) 
{
    time_t      now;
    va_list     args;
    char        format_w_time[1024];

    va_start(args, format);
    now = time(NULL);
    sprintf(format_w_time, "%s: PUBCOOKIE_DEBUG: %s", libpbc_time_string(now), format);
    vfprintf(stderr, format_w_time, args);
    va_end(args);
    return 1;
}

/* get some dubgging into to stdout                                           */
void libpbc_augment_rand_state(unsigned char *array, int len)
{

    struct timeval 	tv; 
    struct timezone 	tz;
    unsigned char	buf[1024];
    pid_t		pid;

    gettimeofday(&tv, &tz);
    memcpy(buf, &tv.tv_usec, sizeof(tv.tv_usec));
    RAND_seed(buf, sizeof(tv.tv_usec));
    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    RAND_seed(buf, sizeof(pid));

}

/* keep 'em guessing                                                          */
void libpbc_rand_malloc()
{

    int			num = 0, i;
    unsigned char	buf[PBC_RAND_MALLOC_BYTES];

    while ( num <= 0 ) {
        RAND_bytes(buf, PBC_RAND_MALLOC_BYTES);
        for( i=0; i<PBC_RAND_MALLOC_BYTES; i++)
            num = num + (int)buf[i];	
    }
    pbc_malloc(num);

}

/* a local malloc and init                                                    */
char *libpbc_alloc_init(int len)
{
    char	*pointer;

    libpbc_rand_malloc();
    if( (pointer = pbc_malloc(len)) ) 
	memset(pointer, 0, len);
    else
        libpbc_abend("libpbc_alloc_init: Failed to malloc space\n");
    return pointer;
}

/*                                                                            */
int libpbc_get_private_key(md_context_plus *ctx_plus)
{

    FILE	*key_fp;
    EVP_PKEY	*key;

    if( ! (key_fp = pbc_fopen(PBC_KEYFILE, "r")) )
        libpbc_abend("libpbc_get_private_key: Could not open keyfile: %s\n",
                        PBC_KEYFILE);

    if( ! (key = (EVP_PKEY *)PEM_ASN1_read((char *(*)())d2i_PrivateKey,
                        PEM_STRING_EVP_PKEY, key_fp, NULL, NULL)) )
        libpbc_abend("libpbc_get_private_key: Could not read keyfile: %s\n",
                        PBC_KEYFILE);

    pbc_fclose(key_fp);
    memcpy(ctx_plus->private_key, key, sizeof(EVP_PKEY));
    return 1;

}

/*                                                                            */
int libpbc_get_public_key(md_context_plus *ctx_plus)
{
    FILE 	*fp;
    X509	*x509;
    EVP_PKEY	*key;

    if( ! (fp = pbc_fopen(PBC_CERTFILE, "r")) )
	libpbc_abend("libpbc_get_public_key: Could not open keyfile: %s\n", 
			PBC_CERTFILE);

    if( ! (x509 = (X509 *) PEM_ASN1_read((char *(*)())d2i_X509, 
	                PEM_STRING_X509, fp, NULL, NULL)) )
        libpbc_abend("libpbc_get_public_key: Could not read cert file: %s\n", 
			PBC_CERTFILE);

    if( ! (key = X509_extract_key(x509)) )
        libpbc_abend("libpbc_get_public_key: Could not convert cert to public key\n");

    pbc_fclose(fp);
    memcpy(ctx_plus->public_key, key, sizeof(EVP_PKEY));
    return 1;
}

/* mallocs a pbc_cookie_data struct                                           */
pbc_cookie_data *libpbc_init_cookie_data()
{
    pbc_cookie_data *cookie_data;

    cookie_data=(pbc_cookie_data *)libpbc_alloc_init(sizeof(pbc_cookie_data));

    return cookie_data;
}

/* init md_context_plus structure                                             */
md_context_plus *libpbc_init_md_context_plus()
{
    md_context_plus	*ctx_plus;
    unsigned char	lil_buf[1];

    ctx_plus=(md_context_plus *)libpbc_alloc_init(sizeof(md_context_plus));

    RAND_bytes(lil_buf, 1);
    switch ((int)lil_buf[0] % 3) {
    case 0:
        ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
        RAND_bytes(lil_buf, 1);
        switch ((int)lil_buf[0] % 2) {
        case 0:
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        case 1:
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
	}
    case 1:
        ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        RAND_bytes(lil_buf, 1);
        switch ((int)lil_buf[0] % 2) {
        case 0:
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        case 1:
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
	}
    case 2:
        ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        RAND_bytes(lil_buf, 1);
        switch ((int)lil_buf[0] % 2) {
        case 0:
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        case 1:
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
	}
    }

    return ctx_plus;
}

/*                                                                            */
void libpbc_get_crypt_key(crypt_stuff *c_stuff)
{
    FILE 		*fp;
//    int			start = 0;
    int			len = 64;
    char		*key_in;
    des_cblock		key;
    int			tries = 5;

    key_in = (char *)libpbc_alloc_init(PBC_BUF_LEN);

    if( ! (fp = pbc_fopen(PBC_CRYPT_KEYFILE, "r")) )
	libpbc_abend("libpbc_crypt_key: Failed open \n");
    
    if( ! fgets(key_in, len, fp) )
	libpbc_abend("libpbc_crypt_key: Failed read \n");
    
    fclose(fp);
    des_string_to_key(key_in, &key);
    memset(key_in, 0, PBC_BUF_LEN);

    libpbc_augment_rand_state(key, sizeof(des_cblock));

    while ( des_key_sched(&key, c_stuff->ks) && tries-- )
	;
    if( ! tries ) 
	libpbc_abend("libpbc_crypt_key: Coudn't build schedule\n");

}

/*                                                                            */
crypt_stuff *libpbc_init_crypt()
{
    crypt_stuff	*c_stuff;

    c_stuff=(crypt_stuff *)libpbc_alloc_init(sizeof(crypt_stuff));

    libpbc_get_crypt_key(c_stuff);

    return c_stuff;
}

/*                                                                            */
unsigned char *libpbc_sign_cookie(unsigned char *cookie_string, md_context_plus *ctx_plus)
{
    unsigned char	*sig;
    unsigned int	sig_len = 0;

    sig = (unsigned char *)libpbc_alloc_init(PBC_SIG_LEN);

    EVP_SignUpdate(ctx_plus->ctx, cookie_string, sizeof(pbc_cookie_data));
    if( EVP_SignFinal(ctx_plus->ctx, sig, &sig_len, ctx_plus->private_key) )
	return sig;
    else
        return (unsigned char *)NULL;
}

/* check a signature after context is established                             */
int libpbc_verify_sig(unsigned char *sig, unsigned char *cookie_string, md_context_plus *ctx_plus)
{
    int	res = 0;

    EVP_VerifyUpdate(ctx_plus->ctx, cookie_string, sizeof(pbc_cookie_data));
    res = EVP_VerifyFinal(ctx_plus->ctx, sig, PBC_SIG_LEN, ctx_plus->public_key);
    if ( res ) 
	return res;
    else
        return 0;

}

unsigned char *libpbc_stringify_seg(unsigned char *start, unsigned char *seg, unsigned len)
{
    int			seg_len;

    seg_len = ( len < strlen(seg) ) ? len : strlen(seg);
    memcpy(start, seg, seg_len);
    return start + len;
}

/*                                                                            */
pbc_cookie_data *libpbc_destringify_cookie_data(pbc_cookie_data *cookie_data) 
{

    (*cookie_data).broken.user[PBC_USER_LEN-1] = '\0';
    (*cookie_data).broken.version[PBC_VER_LEN-1] = '\0';
    (*cookie_data).broken.app_id[PBC_APP_ID_LEN-1] = '\0';
    (*cookie_data).broken.appsrv_id[PBC_APPSRV_ID_LEN-1] = '\0';
    return cookie_data;

}

/* make a cookie_data struct a string                                         */
unsigned char *libpbc_stringify_cookie_data(pbc_cookie_data *cookie_data) 
{
    unsigned char	*cookie_string;
    unsigned char	*p;

    p = cookie_string = (unsigned char *)libpbc_alloc_init(sizeof(pbc_cookie_data));
    p = libpbc_stringify_seg(p, (*cookie_data).broken.user, PBC_USER_LEN);
    p = libpbc_stringify_seg(p, (*cookie_data).broken.version, PBC_VER_LEN);
    p = libpbc_stringify_seg(p, (*cookie_data).broken.appsrv_id, PBC_APPSRV_ID_LEN);
    p = libpbc_stringify_seg(p, (*cookie_data).broken.app_id, PBC_APP_ID_LEN);
    *p = (*cookie_data).broken.type;
    p++;
    *p = (*cookie_data).broken.creds;
    p++;
    memcpy(p, &(*cookie_data).broken.create_ts, sizeof(time_t));
    p = p + sizeof(time_t);
    memcpy(p, &(*cookie_data).broken.last_ts, sizeof(time_t));
    p = p + sizeof(time_t);
    return cookie_string;

}


/* encrypt a string                                                           */
void libpbc_encrypt_cookie(unsigned char *in, unsigned char *out, crypt_stuff *c_stuff, long len) 
{
    int			i = 0;
    des_cblock		ivec;
    unsigned char	ivec_tmp[PBC_INIT_IVEC_LEN]=PBC_INIT_IVEC;

    memcpy(&ivec, ivec_tmp, PBC_INIT_IVEC_LEN);

    des_cfb64_encrypt(in, out, len, c_stuff->ks, &ivec, &i, DES_ENCRYPT);

}

/* decrypt a string                                                         */
void libpbc_decrypt_cookie(unsigned char *in, unsigned char *out, crypt_stuff *c_stuff, long len) 
{
    int			i = 0;
    des_cblock		ivec;
    unsigned char	ivec_tmp[PBC_INIT_IVEC_LEN]=PBC_INIT_IVEC;

    memcpy(&ivec, ivec_tmp, PBC_INIT_IVEC_LEN);

    des_cfb64_encrypt(in, out, len, c_stuff->ks, &ivec, &i, DES_DECRYPT);

}

void libpbc_populate_cookie_data(pbc_cookie_data *cookie_data,
	                  char *user, 
	                  unsigned char type, 
			  unsigned char creds,
			  unsigned char *appsrv_id,
			  unsigned char *app_id) 
{

    strncpy((*cookie_data).broken.user, (unsigned char *)user, PBC_USER_LEN-1);
    strncpy((*cookie_data).broken.version, PBC_VERSION, PBC_VER_LEN-1);
    (*cookie_data).broken.type = type;
    (*cookie_data).broken.creds = creds;
    (*cookie_data).broken.create_ts = time(NULL);
    (*cookie_data).broken.last_ts = time(NULL);
    strncpy((*cookie_data).broken.appsrv_id, appsrv_id, PBC_APPSRV_ID_LEN-1);
    strncpy((*cookie_data).broken.app_id, app_id, PBC_APP_ID_LEN-1);

}

/*                                                                            */
unsigned char *libpbc_sign_bundle_cookie(unsigned char *cookie_string,
			  md_context_plus *ctx_plus,
			  crypt_stuff *c_stuff) 
{

    unsigned char		*cookie;
    unsigned char		*sig;
    unsigned char		buf[PBC_BUF_LEN];
    unsigned char		buf2[PBC_BUF_LEN];

    memset(&buf, 0, PBC_BUF_LEN);
    memset(&buf2, 0, PBC_BUF_LEN);

    if ( ! (sig = libpbc_sign_cookie(cookie_string, ctx_plus)) ) {
        libpbc_debug("libpbc_sign_bundle_cookie: Cookie signing failed\n");
	return (unsigned char *)NULL;
    }
    memcpy(buf, sig, PBC_SIG_LEN);
    memcpy(buf+PBC_SIG_LEN, cookie_string, sizeof(pbc_cookie_data));

    // encrypt cookie
    libpbc_encrypt_cookie(buf, buf2, c_stuff, sizeof(pbc_cookie_data)+PBC_SIG_LEN);

    cookie = (unsigned char *)libpbc_alloc_init(PBC_BUF_LEN);
    base64_encode(buf2, cookie, PBC_SIG_LEN + sizeof(pbc_cookie_data));

    return cookie;
}

/*                                                                            */
/* get public key and initialize verify context                               */
/*                                                                            */
md_context_plus *libpbc_verify_init() 
{
    md_context_plus *ctx_plus;

    ctx_plus = libpbc_init_md_context_plus();
    libpbc_get_public_key(ctx_plus);
    EVP_VerifyInit(ctx_plus->ctx, EVP_md5());

    return ctx_plus;
}

/*                                                                            */
/* get private key and initialize context                                     */
/*                                                                            */
md_context_plus *libpbc_sign_init() 
{
    md_context_plus *ctx_plus;

    ctx_plus = libpbc_init_md_context_plus();
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
			  md_context_plus *ctx_plus,
			  crypt_stuff *c_stuff) 
{

    pbc_cookie_data 		*cookie_data;
    unsigned char		*cookie_string;
    unsigned char		*cookie;

    libpbc_augment_rand_state(user, PBC_USER_LEN);

    cookie_data = libpbc_init_cookie_data();
    libpbc_populate_cookie_data(cookie_data, user, type, creds, appsrv_id, app_id);
    cookie_string = libpbc_stringify_cookie_data(cookie_data);
    cookie = libpbc_sign_bundle_cookie(cookie_string, ctx_plus, c_stuff);

    return cookie;
}

/*                                                                            */
/*  deal with unbundling a cookie                                             */
/*                                                                            */
pbc_cookie_data *libpbc_unbundle_cookie(char *in, md_context_plus *ctx_plus, crypt_stuff *c_stuff) 
{
    pbc_cookie_data	*cookie_data;
    unsigned char	sig[PBC_SIG_LEN];
    unsigned char	buf[PBC_BUF_LEN];
    unsigned char	buf2[PBC_BUF_LEN];

    memset(&buf, 0, PBC_BUF_LEN);
    memset(&buf2, 0, PBC_BUF_LEN);

    if ( strlen(in) < PBC_SIG_LEN ) {
	libpbc_debug("libpbc_unbundle_cookie: cookie %s too short\n", in);
	return 0;
    }

    if( ! base64_decode((unsigned char *)in, buf) ) {
        libpbc_debug("libpbc_unbundle_cookie: Could not decode cookie.\n");
	return 0;
    }

    // decrypt cookie
    libpbc_decrypt_cookie(buf, buf2, c_stuff, sizeof(pbc_cookie_data)+PBC_SIG_LEN);

    /* break cookie in two */
    memcpy(sig, buf2, PBC_SIG_LEN);
    cookie_data = libpbc_init_cookie_data();
    memcpy((*cookie_data).string, buf2+PBC_SIG_LEN, sizeof(pbc_cookie_data));

    if( (libpbc_verify_sig(sig, (*cookie_data).string, ctx_plus)) ) {
        cookie_data = libpbc_destringify_cookie_data(cookie_data);
        return cookie_data;
    }
    else {
        return NULL;
    }
}
    
/*                                                                            */
/*  update last_ts in cookie                                                  */
/*                                                                            */
/* takes a cookie_data structure, updates the time, signs and packages up     */
/* the cookie to be sent back into the world                                  */
/*                                                                            */
unsigned char *libpbc_update_lastts(pbc_cookie_data *cookie_data, md_context_plus *ctx_plus, crypt_stuff *c_stuff)
{
    unsigned char	*cookie_string;
    unsigned char	*cookie;

    (*cookie_data).broken.last_ts = time(NULL);
    cookie_string = libpbc_stringify_cookie_data(cookie_data);
    cookie = libpbc_sign_bundle_cookie(cookie_string, ctx_plus, c_stuff);

    return cookie;

}
    
