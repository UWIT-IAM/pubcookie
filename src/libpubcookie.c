/*
    $Id: libpubcookie.c,v 1.8 1998-07-24 23:14:00 willey Exp $
 */

#ifdef APACHE1_2  /* i'm not sure which of these are needed */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
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
    static char	buf[PBC_1K];

    tm = localtime(&t);
    strftime(buf, sizeof(buf)-1, "%Y/%m/%d %H:%M:%S", tm);

    return buf;
}

/* when things fail too badly to go on ...                                    */
void *libpbc_abend(const char *format,...)
{
    time_t	now;
    va_list	args;
    char	format_w_time[PBC_1K];
    
    va_start(args, format);
    now = time(NULL);
    sprintf(format_w_time, "%s: ABEND: %s", libpbc_time_string(now), format);
    vprintf(format_w_time, args);
    va_end(args);
    exit (EXIT_FAILURE);
}

/*                                                                            */
/* put some debugging info to stdout                                          */
/*                                                                            */
/* perhaps if your server has some other logging method you might want to     */
/* use it here                                                                */
/*                                                                            */
int libpbc_debug(const char *format,...) 
{
    time_t      now;
    va_list     args;
    char        format_w_time[PBC_4K];

    va_start(args, format);
    now = time(NULL);
    sprintf(format_w_time, "%s: PUBCOOKIE_DEBUG: %s", libpbc_time_string(now), format);
    vfprintf(stderr, format_w_time, args);
    va_end(args);
    return 1;
}

/* keep pumping stuff into the random state                                   */
void libpbc_augment_rand_state(unsigned char *array, int len)
{

    struct timeval 	tv; 
    struct timezone 	tz;
    unsigned char	buf[sizeof(tv.tv_usec)];

    gettimeofday(&tv, &tz);
    memcpy(buf, &tv.tv_usec, sizeof(tv.tv_usec));
    RAND_seed(buf, sizeof(tv.tv_usec));

}

/* keep 'em guessing                                                          */
#ifdef APACHE1_2
void libpbc_rand_malloc_p(pool *p)
#else
void libpbc_rand_malloc_np()
#endif
{

    int			num = 0, i;
    unsigned char	buf[PBC_RAND_MALLOC_BYTES];

    while ( num <= 0 ) {
        RAND_bytes(buf, PBC_RAND_MALLOC_BYTES);
        for( i=0; i<PBC_RAND_MALLOC_BYTES; i++)
            num += (int)buf[i];	
    }
    pbc_malloc(num);

}

/*                                                                            */
/* any general startup stuff goes here                                        */
/*                                                                            */
#ifdef APACHE1_2
void libpbc_pubcookie_init_p(pool *p)
#else
void libpbc_pubcookie_init_np()
#endif
{
    unsigned char	buf[sizeof(pid_t)];
    pid_t		pid;

    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    libpbc_augment_rand_state(buf, sizeof(pid));

}

/*                                                                            */
/* any general shutdown stuff goes here                                       */
/*                                                                            */
/*   since i can't find a hook in apache for this there is nothing here, yet  */
/*                                                                            */
#ifdef APACHE1_2
void libpbc_pubcookie_exit_p(pool *p)
#else
void libpbc_pubcookie_exit_np()
#endif
{

}

/* a local malloc and init                                                    */
#ifdef APACHE1_2
char *libpbc_alloc_init_p(pool *p, int len)
#else
char *libpbc_alloc_init_np(int len)
#endif
{
    char	*pointer;

    libpbc_rand_malloc();
    if( (pointer = pbc_malloc(len)) ) 
	memset(pointer, 0, len);
    else
        libpbc_abend("libpbc_alloc_init: Failed to malloc space\n");
    return pointer;
}

/* read and store a private key                                               */
/*    no return value b/c it's fail out or succeed onward                     */
#ifdef APACHE1_2
void libpbc_get_private_key_p(pool *p, md_context_plus *ctx_plus, char *keyfile)
#else
void libpbc_get_private_key_np(md_context_plus *ctx_plus, char *keyfile)
#endif
{

    FILE	*key_fp;
    EVP_PKEY	*key;

    if( ! keyfile )
        libpbc_abend("libpbc_get_private_key: No keyfile specified\n");

    if( ! (key_fp = pbc_fopen(keyfile, "r")) )
        libpbc_abend("libpbc_get_private_key: Could not open keyfile: %s\n", keyfile);

    if( ! (key = (EVP_PKEY *)PEM_ASN1_read((char *(*)())d2i_PrivateKey,
                        PEM_STRING_EVP_PKEY, key_fp, NULL, NULL)) )
        libpbc_abend("libpbc_get_private_key: Could not read keyfile: %s\n", keyfile);

    pbc_fclose(key_fp);
    memcpy(ctx_plus->private_key, key, sizeof(EVP_PKEY));

}

/* read, decode,  and store a public key                                      */
/*    no return value b/c it's fail out or succeed onward                     */
#ifdef APACHE1_2
void libpbc_get_public_key_p(pool *p, md_context_plus *ctx_plus, char *certfile)
#else
void libpbc_get_public_key_np(md_context_plus *ctx_plus, char *certfile)
#endif
{
    FILE 	*fp;
    X509	*x509;
    EVP_PKEY	*key;

    if( ! certfile )
        libpbc_abend("libpbc_get_public_key: No certfile specified\n");

    if( ! (fp = pbc_fopen(certfile, "r")) )
	libpbc_abend("libpbc_get_public_key: Could not open keyfile: %s\n", certfile);

    if( ! (x509 = (X509 *) PEM_ASN1_read((char *(*)())d2i_X509, 
	                PEM_STRING_X509, fp, NULL, NULL)) )
        libpbc_abend("libpbc_get_public_key: Could not read cert file: %s\n", certfile);

    if( ! (key = X509_extract_key(x509)) )
        libpbc_abend("libpbc_get_public_key: Could not convert cert to public key\n");

    pbc_fclose(fp);
    memcpy(ctx_plus->public_key, key, sizeof(EVP_PKEY));
}

/* mallocs a pbc_cookie_data struct                                           */
#ifdef APACHE1_2
pbc_cookie_data *libpbc_init_cookie_data_p(pool *p)
#else
pbc_cookie_data *libpbc_init_cookie_data_np()
#endif
{
    pbc_cookie_data *cookie_data;

    cookie_data=(pbc_cookie_data *)libpbc_alloc_init(sizeof(pbc_cookie_data));

    return cookie_data;
}

/* init md_context_plus structure                                             */
#ifdef APACHE1_2
md_context_plus *libpbc_init_md_context_plus_p(pool *p)
#else
md_context_plus *libpbc_init_md_context_plus_np()
#endif
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
#ifdef APACHE1_2
unsigned char *libpbc_gethostip_p(pool *p)
#else
unsigned char *libpbc_gethostip_np()
#endif
{
    struct hostent      *h;
    char                hostname[PBC_1K];
    unsigned char       *addr;

    gethostname(hostname, sizeof(hostname));
    if( (h = gethostbyname(hostname)) == NULL ) {
        libpbc_abend("%s: host unknown.\n", hostname);
    }
    addr = libpbc_alloc_init(h->h_length);
    memcpy(addr, h->h_addr_list[0], h->h_length);
    
    return addr;
}

/*                                                                            */
char *libpbc_mod_crypt_key(char *in, unsigned char *addr_bytes)
{
    int			i;

    for( i=0; i<PBC_DES_KEY_BUF; ++i ) {
	in[i] ^= addr_bytes[i % sizeof(addr_bytes)];
    }
    
    return in;

}

/*                                                                            */
#ifdef APACHE1_2
void libpbc_get_crypt_key_p(pool *p, crypt_stuff *c_stuff, char *keyfile)
#else
void libpbc_get_crypt_key_np(crypt_stuff *c_stuff, char *keyfile)
#endif
{
    FILE 		*fp;
    char		*key_in;
    unsigned char	*addr;

    key_in = (char *)libpbc_alloc_init(PBC_DES_KEY_BUF);

    if( ! (fp = pbc_fopen(keyfile, "r")) )
	libpbc_abend("libpbc_crypt_key: Failed open\n");
    
    if( fread(key_in, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF)
        libpbc_abend("libpbc_crypt_key: Failed read\n");
    
    fclose(fp);

    addr = libpbc_gethostip();
    memcpy(c_stuff->key_a, libpbc_mod_crypt_key(key_in, addr), sizeof(c_stuff->key_a));

}

/*                                                                            */
#ifdef APACHE1_2
crypt_stuff *libpbc_init_crypt_p(pool *p, char *keyfile)
#else
crypt_stuff *libpbc_init_crypt_np(char *keyfile)
#endif
{
    crypt_stuff	*c_stuff;

    c_stuff=(crypt_stuff *)libpbc_alloc_init(sizeof(crypt_stuff));

    libpbc_get_crypt_key(c_stuff, keyfile);

    return c_stuff;
}

/*                                                                            */
#ifdef APACHE1_2
unsigned char *libpbc_sign_cookie_p(pool *p, unsigned char *cookie_string, md_context_plus *ctx_plus)
#else
unsigned char *libpbc_sign_cookie_np(unsigned char *cookie_string, md_context_plus *ctx_plus)
#endif
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
    return res;

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
#ifdef APACHE1_2
unsigned char *libpbc_stringify_cookie_data_p(pool *p, pbc_cookie_data *cookie_data) 
#else
unsigned char *libpbc_stringify_cookie_data_np(pbc_cookie_data *cookie_data) 
#endif
{
    unsigned char	*cookie_string;
    unsigned char	*ptr;

    ptr = cookie_string = (unsigned char *)libpbc_alloc_init(sizeof(pbc_cookie_data));
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.user, PBC_USER_LEN);
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.version, PBC_VER_LEN);
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.appsrv_id, PBC_APPSRV_ID_LEN);
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.app_id, PBC_APP_ID_LEN);
    *ptr = (*cookie_data).broken.type;
    ptr++;
    *ptr = (*cookie_data).broken.creds;
    ptr++;
    memcpy(ptr, &(*cookie_data).broken.create_ts, sizeof(time_t));
    ptr += sizeof(time_t);
    memcpy(ptr, &(*cookie_data).broken.last_ts, sizeof(time_t));
    ptr += sizeof(time_t);
    return cookie_string;

}

/* get some indices for choosing a key and modifying ivec                     */
int libpbc_get_crypt_index() 
{
    unsigned char	r_byte[1];
    int			index;

    r_byte[0] = '\0';
    while ( r_byte[0] == '\0' ) 
        RAND_bytes(r_byte, 1);
    index = (int)r_byte[0] - (int)r_byte[0]/PBC_DES_INDEX_FOLDER;
    return index;
}

/* encrypt a string                                                           */
int libpbc_encrypt_cookie(unsigned char *in, unsigned char *out, crypt_stuff *c_stuff, long len) 
{
    int				c = 0, i = 0;
    int				tries = 5;
    int				index1, index2;
    des_cblock			key;
    des_cblock			ivec;
    static unsigned char	ivec_tmp[PBC_INIT_IVEC_LEN]=PBC_INIT_IVEC;
    des_key_schedule    	ks;

    index2=libpbc_get_crypt_index();
    memcpy(ivec, &(c_stuff->key_a[index2]), sizeof(ivec));
    for( c=0; c<sizeof(ivec); ++c ) {
	ivec[c] ^= ivec_tmp[i % sizeof(ivec_tmp)];
    }

    /* find a random index into the char key array and make a key shedule */
    des_check_key = 1;
    memset(&key, 0, sizeof(key));
    while ( des_key_sched(&key, ks) != 0 && --tries ) {
        index1=libpbc_get_crypt_index();
	memcpy(key, &(c_stuff->key_a[index1]), sizeof(key));
        des_set_odd_parity(&key);
    }
    if ( ! tries ) {
       libpbc_debug("libpbc_encrypt_cookie: Coudn't find a good key\n");
       return 0;
    }

    des_cfb64_encrypt(in, out, len, ks, &ivec, &i, DES_ENCRYPT);
    libpbc_augment_rand_state(ivec, sizeof(ivec));

    /* stick the indices on the end of the train */
    out[len] = (unsigned char)index1;
    out[len+1] = (unsigned char)index2;
    return 1;

}

/* decrypt a string                                                         */
int libpbc_decrypt_cookie(unsigned char *in, unsigned char *out, crypt_stuff *c_stuff, long len) 
{
    int				c = 0, i = 0;
    int				index1, index2;
    des_cblock			key;
    des_cblock			ivec;
    static unsigned char	ivec_tmp[PBC_INIT_IVEC_LEN]=PBC_INIT_IVEC;
    des_key_schedule    	ks;

    /* grab those two extra btyes off the tail */
    index1 = (int)in[len];
    index2 = (int)in[len+1];

    memcpy(ivec, &(c_stuff->key_a[index2]), sizeof(ivec));
    for( c=0; c<sizeof(ivec); ++c ) {
	ivec[c] ^= ivec_tmp[i % sizeof(ivec_tmp)];
    }

    /* use the supplied index into the char key array and make a key shedule */
    memcpy(key, &(c_stuff->key_a[index1]), sizeof(key));
    des_set_odd_parity(&key);
    if ( des_key_sched(&key, ks) ) {
       libpbc_debug("libpbc_decrypt_cookie: Didn't derive a good key\n");
       return 0;
    }

    des_cfb64_encrypt(in, out, len, ks, &ivec, &i, DES_DECRYPT);

    return 1;

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
#ifdef APACHE1_2
unsigned char *libpbc_sign_bundle_cookie_p(pool *p, 
	                  unsigned char *cookie_string,
			  md_context_plus *ctx_plus,
			  crypt_stuff *c_stuff) 
#else
unsigned char *libpbc_sign_bundle_cookie_np(unsigned char *cookie_string,
			  md_context_plus *ctx_plus,
			  crypt_stuff *c_stuff) 
#endif
{

    unsigned char		*cookie;
    unsigned char		*sig;
    unsigned char		buf[PBC_4K];
    unsigned char		buf2[PBC_4K];

    memset(&buf, 0, sizeof(buf));
    memset(&buf2, 0, sizeof(buf2));

    if ( ! (sig = libpbc_sign_cookie(cookie_string, ctx_plus)) ) {
        libpbc_debug("libpbc_sign_bundle_cookie: Cookie signing failed\n");
	return (unsigned char *)NULL;
    }
    memcpy(buf, sig, PBC_SIG_LEN);
    memcpy(buf+PBC_SIG_LEN, cookie_string, sizeof(pbc_cookie_data));

    /* two bytes get added on in libpbc_encrypt_cookie */
    if ( ! libpbc_encrypt_cookie(buf, buf2, c_stuff, sizeof(pbc_cookie_data)+PBC_SIG_LEN) )
	return 0;

    cookie = (unsigned char *)libpbc_alloc_init(PBC_4K);
    base64_encode(buf2, cookie, PBC_SIG_LEN + sizeof(pbc_cookie_data) + 2);

    return cookie;
}

/*                                                                            */
/* get public key and initialize verify context                               */
/*                                                                            */
#ifdef APACHE1_2
md_context_plus *libpbc_verify_init_p(pool *p, char *certfile) 
#else
md_context_plus *libpbc_verify_init_np(char *certfile) 
#endif
{
    md_context_plus *ctx_plus;

    ctx_plus = libpbc_init_md_context_plus();
    libpbc_get_public_key(ctx_plus, certfile);
    EVP_VerifyInit(ctx_plus->ctx, EVP_md5());

    return ctx_plus;
}

/*                                                                            */
/* get private key and initialize context                                     */
/*                                                                            */
#ifdef APACHE1_2
md_context_plus *libpbc_sign_init_p(pool *p, char *keyfile) 
#else
md_context_plus *libpbc_sign_init_np(char *keyfile) 
#endif
{
    md_context_plus *ctx_plus;

    ctx_plus = libpbc_init_md_context_plus();
    libpbc_get_private_key(ctx_plus, keyfile);
    EVP_SignInit(ctx_plus->ctx, EVP_md5());
    return ctx_plus;
}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
#ifdef APACHE1_2
unsigned char *libpbc_get_cookie_p(pool *p, char *user, 
	                  unsigned char type, 
			  unsigned char creds,
			  unsigned char *appsrv_id,
			  unsigned char *app_id,
			  md_context_plus *ctx_plus,
			  crypt_stuff *c_stuff) 
#else
unsigned char *libpbc_get_cookie_np(char *user, 
	                  unsigned char type, 
			  unsigned char creds,
			  unsigned char *appsrv_id,
			  unsigned char *app_id,
			  md_context_plus *ctx_plus,
			  crypt_stuff *c_stuff) 
#endif
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
#ifdef APACHE1_2
pbc_cookie_data *libpbc_unbundle_cookie_p(pool *p, char *in, md_context_plus *ctx_plus, crypt_stuff *c_stuff) 
#else
pbc_cookie_data *libpbc_unbundle_cookie_np(char *in, md_context_plus *ctx_plus, crypt_stuff *c_stuff) 
#endif
{
    pbc_cookie_data	*cookie_data;
    unsigned char	sig[PBC_SIG_LEN];
    unsigned char	buf[PBC_4K];
    unsigned char	buf2[PBC_4K];

    memset(&buf, 0, sizeof(buf));
    memset(&buf2, 0, sizeof(buf2));

    if ( strlen(in) < PBC_SIG_LEN || strlen(in) > PBC_4K ) {
	libpbc_debug("libpbc_unbundle_cookie: malformed cookie %s\n", in);
	return 0;
    }

    if( ! base64_decode((unsigned char *)in, buf) ) {
        libpbc_debug("libpbc_unbundle_cookie: Could not decode cookie.\n");
	return 0;
    }

    if ( ! libpbc_decrypt_cookie(buf, buf2, c_stuff, sizeof(pbc_cookie_data)+PBC_SIG_LEN) )
	return 0;

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
#ifdef APACHE1_2
unsigned char *libpbc_update_lastts_p(pool *p, pbc_cookie_data *cookie_data, md_context_plus *ctx_plus, crypt_stuff *c_stuff)
#else
unsigned char *libpbc_update_lastts_np(pbc_cookie_data *cookie_data, md_context_plus *ctx_plus, crypt_stuff *c_stuff)
#endif
{
    unsigned char	*cookie_string;
    unsigned char	*cookie;

    (*cookie_data).broken.last_ts = time(NULL);
    cookie_string = libpbc_stringify_cookie_data(cookie_data);
    cookie = libpbc_sign_bundle_cookie(cookie_string, ctx_plus, c_stuff);

    return cookie;

}
