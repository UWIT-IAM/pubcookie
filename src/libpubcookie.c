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

    this is the pubcookie library

 */

/* 
    $Id: libpubcookie.c,v 2.36 2002-08-06 16:01:07 greenfld Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if defined (APACHE1_3)
# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"
#endif

#if defined (WIN32)

# include <windows.h>
typedef  int pid_t;  /* win32 process ID */
# include <process.h>  /* getpid */

#else /* WIN32 */

# ifdef HAVE_STDIO_H
#  include <stdio.h>
# endif /* HAVE_STDIO_H */

# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif /* HAVE_STDLIB_H */

# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# endif /* HAVE_STDARG_H */

# ifdef HAVE_SYSLOG_H
#  include <syslog.h>
# endif /* HAVE_SYSLOG_H */

# ifdef HAVE_TIME_H
#  include <time.h>
# endif /* HAVE_TIME_H */

# ifdef HAVE_STRING_H
#  include <string.h>
# endif /* HAVE_STRING_H */

# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# endif /* HAVE_SYS_TIME_H */

# ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
# endif /* HAVE_SYS_UTSNAME_H */

# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif /* HAVE_NETINET_IN_H */

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif /* HAVE_UNISTD_H */

# ifdef HAVE_NETDB_H
#  include <netdb.h>
# endif /* HAVE_NETDB_H */

#endif /* WIN32 */


#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/des.h>
# include <openssl/rand.h>
# include <openssl/err.h>
#else
# include <pem.h>
# include <des.h>
# include <rand.h>
# include <err.h>
#endif /* OPENSSL_IN_DIR */

/* pubcookie lib stuff */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "strlcpy.h"
#include "security.h"
#include "pbc_logging.h"

/* CONSTANTS */

/* why is this user being sent back, well the redirect reason will tell ya */
const char *redirect_reason[] = {
    "NONE",			/* 0 */
    "No G or S cookie",		/* 1 */
    "Can't unbundle S cookie",	/* 2 */
    "S cookie hard expired",	/* 3 */
    "S cookie inact expired",	/* 4 */
    "speed up that loop",	/* 5 */
    "Can't unbundle G cookie",	/* 6 */
    "G cookie expired",		/* 7 */
    "Wrong appid",		/* 8 */
    "Wrong app server id",	/* 9 */
    "Wrong version id",		/* 10 */
    "Wrong creds"		/* 11 */
};

const char *get_my_hostname()
{
    return libpbc_get_cryptname();
}

/** 
 * find the credential id value for an authtype name
 * @param name the name of the authtype
 * @returns either PBC_CREDS_NONE or the credential id to pass in the cookie
 */
const char libpbc_get_credential_id(const char *name)
{
    if (!strcasecmp(name, "uwnetid")) {
         libpbc_debug("WARNING: AuthType %s will not be supported in future versions - user AuthType WebISO\n", name);
         return PBC_BASIC_CRED_ID;
    }
    if (!strcasecmp(name, "webiso") ||
        !strcasecmp(name, "webiso-vanilla")) {
	return PBC_BASIC_CRED_ID; /* flavor_basic */
    } else if (!strcasecmp(name, "webiso-getcred")) {
	return PBC_GETCRED_CRED_ID; /* flavor_getcred */
    } else {
	return PBC_CREDS_NONE;
    }
}

/*
 * print the passed bytes
 */
static void print_hex_nybble(FILE *f,int n)
{
  char *hex="0123456789abcdef";
  n&=0x0f;
  fputc(hex[n],f);
}

static void print_hex_bytes(FILE *f,void *s_in,int len)
{
  unsigned char *s=(unsigned char *)s_in;
  fprintf(f,"[%lx]",(long)s);
  if(s==0) {
    fprintf(f,"(null)");
    return;
  }
  while(len-->0) {
    print_hex_nybble(f,(*s)>>4);
    print_hex_nybble(f,(*s));
    s++;
  }
}

/* dummy des stub */
#define zzdes_cfb64_encrypt(xin,xout,xlen,xks,xivec,xi,xdirection) memcpy(xout,xin,len)

#ifdef DEBUG_ENCRYPT_COOKIE
/* really has more to do with aligning the buffers */
static unsigned char cfb_iv[8]={0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
static unsigned char cfb_tmp[8];

static void xdes_cfb64_encrypt(const unsigned char *in,unsigned char *out,long length,des_key_schedule schedule,des_cblock *ivec,int *num,int enc)
{
#ifdef RUBBISH
  while(length-- > 0)
    *out++ = (*in++)^1;
#endif

  long long xin[4200];
  long long xout[4200];

  memcpy(&xin,in,length);
  memcpy(cfb_tmp,cfb_iv,sizeof(cfb_iv));
  des_cfb64_encrypt(&xin,&xout,length,schedule,&cfb_tmp,num,enc);
  memcpy(out,&xout,length);
}
#define des_cfb64_encrypt xdes_cfb64_encrypt
#endif

/* get a nice pretty log time                                                 */
char *libpbc_time_string(time_t t)
{ 
    struct tm	*tm;
    static char	buf[PBC_1K];

    tm = localtime(&t);
    strftime(buf, sizeof(buf)-1, "%Y/%m/%d %H:%M:%S", tm);

    return buf;
}

#if defined (WIN32)
extern int Debug_Trace;
extern FILE *debugFile;  /* from PubcookieFilter */
#endif

/* when things fail too badly to go on ...                                    */
void *libpbc_abend(const char *format,...)
{
    time_t	now;
    va_list	args;
    char	format_w_time[PBC_1K];
#if defined (WIN32)
    char        buff[PBC_4K];
#endif
    
    va_start(args, format);
    now = time(NULL);
#if defined (_GNU_SOURCE)
    snprintf(format_w_time, sizeof(format_w_time), "%s: ABEND: %s", libpbc_time_string(now), format);
#else
    sprintf(format_w_time, "%s: ABEND: %s", libpbc_time_string(now), format);
#endif
#if defined (WIN32)
    vsprintf(buff, format_w_time, args);
    OutputDebugString(buff);  /* win32 debugging */
    if ( debugFile )
        fprintf(debugFile,"%s",buff);
#else
    vfprintf(stderr,format_w_time, args);
#endif
    va_end(args);
#if defined (WIN32)
    return NULL;
#else
    exit(EXIT_FAILURE);
#endif
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
#if defined (WIN32)
    char        buff[PBC_4K];
#endif

    va_start(args, format);
    now = time(NULL);
#if defined (_GNU_SOURCE)
    snprintf(format_w_time, sizeof(format_w_time)-1, "%s: PUBCOOKIE_DEBUG: %s", libpbc_time_string(now), format);
#else
    sprintf(format_w_time, "%s: PUBCOOKIE_DEBUG: %s", libpbc_time_string(now), format);
#endif
#if defined (WIN32)
    if ( Debug_Trace ) {
	vsprintf(buff, format_w_time, args);
	OutputDebugString(buff);  /* win32 debugging */
	if ( debugFile )
	    fprintf(debugFile,"%s",buff);
	}
#else
    vfprintf(stderr, format_w_time, args);
#endif
    va_end(args);
    return 1;
}

void libpbc_void(void *thing) {
}

void *malloc_debug(size_t x) {
    void *p;
    p = malloc (x);
    libpbc_debug("  pbc_malloc(%d)= x%X\n",x,p);
    return p;
}

void free_debug(void *p) {
    libpbc_debug("  pbc_free= x%X\n",p);
    free(p);
}

/* keep pumping stuff into the random state                                   */
void libpbc_augment_rand_state(unsigned char *array, int len)
{

/*  Window only has milliseconds */
#if defined (WIN32)
    SYSTEMTIME   ts;
    unsigned char buf[sizeof(ts.wMilliseconds)];

    GetLocalTime(&ts);
    memcpy(buf, &ts.wMilliseconds, sizeof(ts.wMilliseconds));
    RAND_seed(buf, sizeof(ts.wMilliseconds));
#else
    struct timeval 	tv; 
    struct timezone 	tz;
    unsigned char	buf[sizeof(tv.tv_usec)];

    gettimeofday(&tv, &tz);
    memcpy(buf, &tv.tv_usec, sizeof(tv.tv_usec));
    RAND_seed(buf, sizeof(tv.tv_usec));
#endif

}

/* keep 'em guessing                                                          */
#ifdef APACHE
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
#ifdef APACHE
void libpbc_pubcookie_init_p(pool *p)
#else
void libpbc_pubcookie_init_np()
#endif
{
    unsigned char	buf[sizeof(pid_t)];
    pid_t		pid;

    /*  libpbc_debug("libpbc_pubcookie_init\n"); */

    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    libpbc_augment_rand_state(buf, sizeof(pid));

    if (security_init()) {
        syslog(LOG_ERR, "security_init failed");
        exit(1);
    }
}

/* a local malloc and init                                                    */
#ifdef APACHE
unsigned char *libpbc_alloc_init_p(pool *p, int len)
#else
unsigned char *libpbc_alloc_init_np(int len)
#endif
{
    unsigned char	*pointer;

/* Skip the rand_malloc for Windows ISAPI filter, too much overhead */
#if !defined (WIN32)
    libpbc_rand_malloc();
#endif

    if( (pointer = (unsigned char *)pbc_malloc(len)) ) 
	memset(pointer, 0, len);
    else
        libpbc_abend("libpbc_alloc_init: Failed to malloc space\n");
    return pointer;
}

static void limit_strcpy(char *dst, char *src, int siz)
{
    while(siz-->1) {
        char ch= *src++;
        if(ch==0)
            break;
        *dst++=ch;
    }
    if(siz>0)
        *dst=0;
}

/* read and store a private key                                               */
/*    no return value b/c it's fail out or succeed onward                     */
#ifdef APACHE
int libpbc_get_private_key_p(pool *p, md_context_plus *ctx_plus, char *keyfile)
#else
int libpbc_get_private_key_np(md_context_plus *ctx_plus, char *keyfile)
#endif
{

    FILE	*key_fp;
    EVP_PKEY	*key;

    limit_strcpy(ctx_plus->key_file,keyfile,sizeof(ctx_plus->key_file));

    if( ! keyfile ) {
        libpbc_debug("libpbc_get_private_key: No keyfile specified\n");
	return PBC_FAIL;
    }

    if( ! (key_fp = pbc_fopen(keyfile, "r")) ) {
        libpbc_debug("libpbc_get_private_key: Could not open keyfile: %s\n", keyfile);
        return PBC_FAIL;
    }

#ifdef DEBUG_ENCRYPT_COOKIE
    libpbc_debug("libpbc_get_private_key: reading private key '%s'\n", keyfile);
#endif

    if( ! (key = (EVP_PKEY *)PEM_ASN1_read((char *(*)())d2i_PrivateKey,
		  PEM_STRING_EVP_PKEY, key_fp, NULL, NULL, NULL)) ) {
        libpbc_debug("libpbc_get_private_key: Could not read keyfile: %s\n", keyfile);
        return PBC_FAIL;
    }

    pbc_fclose(key_fp);
    memcpy(ctx_plus->private_key, key, sizeof(EVP_PKEY));

    return PBC_OK;
}

/* read, decode,  and store a public key                                      */
/*    no return value b/c it's fail out or succeed onward                     */
#ifdef APACHE
int libpbc_get_public_key_p(pool *p, md_context_plus *ctx_plus, char *certfile)
#else
int libpbc_get_public_key_np(md_context_plus *ctx_plus, char *certfile)
#endif
{
    FILE 	*fp;
    X509	*x509;
    EVP_PKEY	*key;

    limit_strcpy(ctx_plus->key_file, certfile, sizeof(ctx_plus->key_file));

    if( ! certfile ) {
        libpbc_debug("libpbc_get_public_key: No certfile specified\n");
        return PBC_FAIL;
    }

    if( ! (fp = pbc_fopen(certfile, "r")) ) {
	libpbc_debug("libpbc_get_public_key: Could not open keyfile: %s\n", certfile);
        return PBC_FAIL;
    }

#ifdef DEBUG_ENCRYPT_COOKIE
    libpbc_debug("libpbc_get_public_key: reading public cert '%s'\n", certfile);
#endif

    if( ! (x509 = (X509 *) PEM_ASN1_read((char *(*)())d2i_X509, 
		           PEM_STRING_X509, fp, NULL, NULL, NULL)) ) {
        libpbc_debug("libpbc_get_public_key: Could not read cert file: %s\n", certfile);
        return PBC_FAIL;
    }

    if( ! (key = X509_extract_key(x509)) ) {
        libpbc_debug("libpbc_get_public_key: Could not convert cert to public key\n");
        return PBC_FAIL;
    }

    pbc_fclose(fp);
    memcpy(ctx_plus->public_key, key, sizeof(EVP_PKEY));

    return PBC_OK;
}

/* mallocs a pbc_cookie_data struct                                           */
#ifdef APACHE
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
#ifdef APACHE
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
	    break;
        case 1:
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
	    break;
	}
	break;
    case 1:
        ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        RAND_bytes(lil_buf, 1);
        switch ((int)lil_buf[0] % 2) {
        case 0:
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
	    break;
        case 1:
            ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
	    break;
	}    
	break;
    case 2:
        ctx_plus->private_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
        RAND_bytes(lil_buf, 1);
        switch ((int)lil_buf[0] % 2) {
        case 0:
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
	    break;
        case 1:
            ctx_plus->public_key=(EVP_PKEY *)libpbc_alloc_init(sizeof(EVP_PKEY));
            ctx_plus->ctx=(EVP_MD_CTX *)libpbc_alloc_init(sizeof(EVP_MD_CTX));
	    break;
	}
	break;
    }

    return ctx_plus;
}

/*                                                                            */
#ifdef APACHE
void libpbc_free_md_context_plus_p(pool *p, md_context_plus *ctx_plus)
#else
void libpbc_free_md_context_plus_np(md_context_plus *ctx_plus)
#endif
{
    pbc_free(ctx_plus->ctx);
    pbc_free(ctx_plus->public_key);
    pbc_free(ctx_plus->private_key);
    pbc_free(ctx_plus);
}

/*                                                                            */
#ifdef APACHE
unsigned char *libpbc_gethostip_p(pool *p)
#else
unsigned char *libpbc_gethostip_np()
#endif
{
    struct hostent      *h;
    unsigned char       *addr;

#if defined (WIN32)
    char                hostname[PBC_1K];
    int                 err;
    
    hostname[0] = '\0';
    err=gethostname(hostname, sizeof(hostname));
    if( (h = gethostbyname(hostname)) == NULL ) {
        libpbc_abend("gethostname error= %d, %s: host unknown.\n", err,hostname);
	return NULL;
    }
#else
    struct utsname      myname;

    if ( uname(&myname) < 0 ) {
	libpbc_abend("problem doing uname lookup\n");
	return NULL;
    }

    if ( (h = gethostbyname(myname.nodename)) == NULL ) {
       	libpbc_abend("%s: host unknown.\n", myname.nodename);
	return NULL;
    }
#endif

    addr = libpbc_alloc_init(h->h_length);
    memcpy(addr, h->h_addr_list[0], h->h_length);
    
    return addr;
}

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile(const char *peername, char *buf)
{
    strlcpy(buf, PBC_KEY_DIR, 1024);
    if (buf[strlen(buf)-1] != '/') {
	strlcat(buf, "/", 1024);
    }
    strlcat(buf, peername, 1024);
}
    
/**
 * generates a random key for peer and writes it to the disk
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
#ifdef APACHE
int libpbc_generate_crypt_key_p(pool *p, const char *peer)
#else
int libpbc_generate_crypt_key_np(const char *peer)
#endif
{
    unsigned char buf[PBC_DES_KEY_BUF];
    char keyfile[1024];
    FILE *f;

    RAND_bytes(buf, PBC_DES_KEY_BUF);

    make_crypt_keyfile(peer, keyfile);
    if (!(f = pbc_fopen(keyfile, "w"))) {
        return PBC_FAIL;
    }
    fwrite(buf, sizeof(char), PBC_DES_KEY_BUF, f);
    fclose(f);

    return PBC_OK;
}

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the PB_C_DES_KEY_BUF-sized key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
#ifdef APACHE
int libpbc_set_crypt_key_p(pool *p, const char *key, const char *peer)
#else
int libpbc_set_crypt_key_np(const char *key, const char *peer)
#endif
{
    char keyfile[1024];
    FILE *f;

    make_crypt_keyfile(peer, keyfile);
    if (!(f = pbc_fopen(keyfile, "w"))) {
	return PBC_FAIL;
    }
    fwrite(key, sizeof(char), PBC_DES_KEY_BUF, f);
    fclose(f);

    return PBC_OK;
}

/*                                                                           */
#ifdef APACHE
int libpbc_get_crypt_key_p(pool *p, crypt_stuff *c_stuff, const char *peer)
#else
int libpbc_get_crypt_key_np(crypt_stuff *c_stuff, const char *peer)
#endif
{
    FILE             *fp;
    char             *key_in;
    char keyfile[1024];

/*  libpbc_debug("libpbc_get_crypt_key\n"); */

    make_crypt_keyfile(peer, keyfile);

    key_in = (char *)libpbc_alloc_init(PBC_DES_KEY_BUF);

    if( ! (fp = pbc_fopen(keyfile, "rb")) ) { /* win32 - must be binary read */
        libpbc_debug("libpbc_get_crypt_key: Failed open: %s\n", keyfile);
        return PBC_FAIL;
    }
    
    if( fread(key_in, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
        libpbc_debug("libpbc_get_crypt_key: Failed read: %s\n", keyfile);
	pbc_fclose(fp);
	return PBC_FAIL;
    }
    
#ifdef DEBUG_ENCRYPT_COOKIE
    libpbc_debug("libpbc_get_crypt_key: reading crypt key '%s'\n", keyfile);
#endif

    pbc_fclose(fp);

    memcpy(c_stuff->key_a, key_in, sizeof(c_stuff->key_a));
    pbc_free(key_in);

    return PBC_OK;
}

/*                                                                           */
#ifdef APACHE
crypt_stuff *libpbc_init_crypt_p(pool *p, char *peername)
#else
crypt_stuff *libpbc_init_crypt_np(char *peername)
#endif
{
    crypt_stuff	*c_stuff;

    c_stuff=(crypt_stuff *)libpbc_alloc_init(sizeof(crypt_stuff));

    if ( libpbc_get_crypt_key(c_stuff, peername) == PBC_OK ) {
#ifdef DEBUG_ENCRYPT_COOKIE
        libpbc_debug("read key >");
        print_hex_bytes(stderr,c_stuff->key_a,sizeof(c_stuff->key_a));
#endif
        return c_stuff;
    } else {
	libpbc_free_crypt(c_stuff);
	return NULL;
    }
}

/*                                                                           */
#ifdef APACHE
void libpbc_free_crypt_p(pool *p, crypt_stuff *c_stuff)
#else
void libpbc_free_crypt_np(crypt_stuff *c_stuff)
#endif
{
    pbc_free(c_stuff);  
}

/*                                                                            */
#ifdef APACHE
unsigned char *libpbc_sign_cookie_p(pool *p, unsigned char *cookie_string, md_context_plus *ctx_plus)
#else
unsigned char *libpbc_sign_cookie_np(unsigned char *cookie_string, md_context_plus *ctx_plus)
#endif
{
    unsigned char	*sig;
    unsigned int	sig_len = 0;

#ifdef DEBUG_ENCRYPT_COOKIE
    libpbc_debug("libpbc_sign_cookie: signing with key '%s'\n",ctx_plus->key_file);
#endif

    sig = (unsigned char *)libpbc_alloc_init(PBC_SIG_LEN);

    EVP_SignInit(ctx_plus->ctx, EVP_md5());
    EVP_SignUpdate(ctx_plus->ctx, cookie_string, sizeof(pbc_cookie_data));
    if( EVP_SignFinal(ctx_plus->ctx, sig, &sig_len, ctx_plus->private_key) )
        return sig;
    else {
        pbc_free(sig);
        return (unsigned char *)NULL;
    }
}

/* check a signature after context is established                             */
int libpbc_verify_sig(unsigned char *sig, unsigned char *cookie_string, md_context_plus *ctx_plus)
{
    int	res = 0;

#ifdef DEBUG_ENCRYPT_COOKIE
    libpbc_debug("libpbc_verify_cookie: verify with key '%s'\n",ctx_plus->key_file);
#endif

    EVP_VerifyInit(ctx_plus->ctx, EVP_md5());
    EVP_VerifyUpdate(ctx_plus->ctx, cookie_string, sizeof(pbc_cookie_data));
    res = EVP_VerifyFinal(ctx_plus->ctx, sig, PBC_SIG_LEN, ctx_plus->public_key);

    return res;

}

unsigned char *libpbc_stringify_seg(unsigned char *start, unsigned char *seg, unsigned len)
{
    int			seg_len;

    seg_len = ( len < strlen((const char *)seg) ) ? len : strlen((const char *)seg);
    memcpy(start, seg, seg_len);
    return start + len;
}

/*                                                                            */
pbc_cookie_data *libpbc_destringify_cookie_data(pbc_cookie_data *cookie_data) 
{

    (*cookie_data).broken.user[PBC_USER_LEN-1] = '\0';
    (*cookie_data).broken.version[PBC_VER_LEN-1] = '\0';
    (*cookie_data).broken.appid[PBC_APP_ID_LEN-1] = '\0';
    (*cookie_data).broken.appsrvid[PBC_APPSRV_ID_LEN-1] = '\0';
    return cookie_data;

}

/* package the cookie info for transit                                        */
/*   - make the cookie_data struct a string                                   */
/*   - do network byte order conversion                                       */
#ifdef APACHE
unsigned char *libpbc_stringify_cookie_data_p(pool *p, pbc_cookie_data *cookie_data) 
#else
unsigned char *libpbc_stringify_cookie_data_np(pbc_cookie_data *cookie_data) 
#endif
{
    unsigned char	*cookie_string;
    unsigned char	*ptr;
    int			temp;

    ptr = cookie_string = (unsigned char *)libpbc_alloc_init(sizeof(pbc_cookie_data));
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.user, PBC_USER_LEN);
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.version, PBC_VER_LEN);
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.appsrvid, PBC_APPSRV_ID_LEN);
    ptr = libpbc_stringify_seg(ptr, (*cookie_data).broken.appid, PBC_APP_ID_LEN);
    *ptr = (*cookie_data).broken.type;
    ptr++;

    *ptr = (*cookie_data).broken.creds;
    ptr++;

    temp = htonl((*cookie_data).broken.pre_sess_token);
    memcpy(ptr, &temp, sizeof(int));
    ptr += sizeof(int);

    temp = htonl((*cookie_data).broken.create_ts);
    memcpy(ptr, &temp, sizeof(time_t));
    ptr += sizeof(time_t);

    temp = htonl((*cookie_data).broken.last_ts);
    memcpy(ptr, &temp, sizeof(time_t));
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
/*                                                                            */
/* using DES cfp64 (Cipher Feed Back mode)                                    */
/*                                                                            */
/* two indexes are chosed and passed with the encryped blob                   */
/*   one is an index into the blob of key bits another is an index into       */
/*   the possible initialization vectors                                      */
/*                                                                            */
int libpbc_encrypt_cookie(unsigned char *in, unsigned char *out, crypt_stuff *c_stuff, long len) 
{
    int				c = 0, i = 0;
    int				tries = 5;
    int				index1 = 0; 
    int				index2 = 0;
    des_cblock			key;
    des_cblock			ivec;
    static unsigned char	ivec_tmp[PBC_INIT_IVEC_LEN]=PBC_INIT_IVEC;
    des_key_schedule    	ks;

    /* ... later, Steve reflects that keeping the ivec secret is not needed  */
    /* so why don't we just pass the ivec instead of this index into a small */
    /* array of possible ivecs? ...                                          */
    index2=libpbc_get_crypt_index();
    memcpy(ivec, &(c_stuff->key_a[index2]), sizeof(ivec));
    for( c=0; c<sizeof(ivec); ++c ) {
	ivec[c] ^= ivec_tmp[i % sizeof(ivec_tmp)];
    }

    /* find a random index into the char key array and make a key shedule */

/*  libpbc_debug("libpbc_encrypt_cookie: before setting des_check_key= %d\n",des_check_key); */

    memset(key, 0, sizeof(key));
    while ( des_set_key_checked(&key, ks) < 0 && --tries ) {
        index1=libpbc_get_crypt_index();
	memcpy(key, &(c_stuff->key_a[index1]), sizeof(key));
        des_set_odd_parity(&key);
    }

    if ( ! tries ) {
       libpbc_debug("libpbc_encrypt_cookie: Couldn't find a good key\n");
       return 0;
    }

#ifdef DEBUG_ENCRYPT_COOKIE
    fprintf(stderr,"index1=%d index2=%d len=%ld key=",index1,index2,len);
    print_hex_bytes(stderr,key,sizeof(key));
    fprintf(stderr," ivec=");
    print_hex_bytes(stderr,ivec,sizeof(ivec));
    fprintf(stderr," in=");
    print_hex_bytes(stderr,in,len+2);
    fprintf(stderr,"\n");
#endif

    des_cfb64_encrypt(in, out, len, ks, &ivec, &i, DES_ENCRYPT);
    libpbc_augment_rand_state(ivec, sizeof(ivec));

    /* stick the indices on the end of the train */
    out[len] = (unsigned char)index1;
    out[len+1] = (unsigned char)index2;

#ifdef DEBUG_ENCRYPT_COOKIE
    fprintf(stderr,"out=");
    print_hex_bytes(stderr,out,len+2);
    fprintf(stderr,"\n");
#endif

    return 1;

}

/* decrypt a string                                                         */
int libpbc_decrypt_cookie(unsigned char *in, unsigned char *out, crypt_stuff *c_stuff, long len) 
{
    int				c = 0, i = 0;
    int				index1 = 0;
    int				index2 = 0;
    des_cblock			key;
    des_cblock			ivec;
    static unsigned char	ivec_tmp[PBC_INIT_IVEC_LEN]=PBC_INIT_IVEC;
    des_key_schedule    	ks;

    /* libpbc_debug("libpbc_decrypt_cookie: hello\n"); */

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
    if ( des_set_key_checked(&key, ks) ) {
       libpbc_debug("libpbc_decrypt_cookie: Didn't derive a good key\n");
       return 0;
    }

#ifdef DEBUG_ENCRYPT_COOKIE
    fprintf(stderr,"index1=%d index2=%d len=%ld key=",index1,index2,len);
    print_hex_bytes(stderr,key,sizeof(key));
    fprintf(stderr," ivec=");
    print_hex_bytes(stderr,ivec,sizeof(ivec));
    fprintf(stderr," in=");
    print_hex_bytes(stderr,in,len+2);
    fprintf(stderr,"\n");
#endif

    des_cfb64_encrypt(in, out, len, ks, &ivec, &i, DES_DECRYPT);

#ifdef DEBUG_ENCRYPT_COOKIE
    fprintf(stderr,"out=");
    print_hex_bytes(stderr,out,len);
    fprintf(stderr,"\n");
#endif

    return 1;

}

/* put stuff in the cookie structure                                          */
/*  note: we don't do network byte order conversion here,                     */
/*  instead we leave that for stringify                                       */
/*                                                                            */
void libpbc_populate_cookie_data(pbc_cookie_data *cookie_data,
	                  unsigned char *user, 
	                  unsigned char type, 
			  unsigned char creds,
			  int pre_sess_token,
                          time_t expire,
			  unsigned char *appsrvid,
			  unsigned char *appid) 
{

    /* libpbc_debug("libpbc_populate_cookie_data\n"); */

    strncpy((char *)(*cookie_data).broken.user, (const char *)user, PBC_USER_LEN-1);
    strncpy((char *)(*cookie_data).broken.version, PBC_VERSION, PBC_VER_LEN-1);
    (*cookie_data).broken.type = type;
    (*cookie_data).broken.creds = creds;
    (*cookie_data).broken.pre_sess_token = pre_sess_token;
    (*cookie_data).broken.create_ts = time(NULL);
    (*cookie_data).broken.last_ts = expire;
    strncpy((char *)(*cookie_data).broken.appsrvid, (const char *)appsrvid, PBC_APPSRV_ID_LEN-1);
    strncpy((char *)(*cookie_data).broken.appid, (const char *)appid, PBC_APP_ID_LEN-1);

}

/**
 * unfortunately libpbc_sign_bundle_cookie and libpbc_unbundle are not    
 * symmetrical in the data they deal with.  the bundle takes the stringified
 * info and the unbundle returns a struct.  maybe someday i'll clean that up
 *                                                                            
 * @param cookie_string pointer to the cookie buffer of length
 * sizeof(pbc_cookie_data)
 * @param peer the peer this cookie is destined for (NULL for myself)
 * @returns a pointer to a newly malloc()ed base64 string
 */
#ifdef APACHE
unsigned char *libpbc_sign_bundle_cookie_p(pool *p, 
					   unsigned char *cookie_string,
					   const char *peer)
#else
unsigned char *libpbc_sign_bundle_cookie_np(unsigned char *cookie_string,
					    const char *peer)
#endif
{
    unsigned char		*cookie;
    char *out;
    int outlen;

    if (libpbc_mk_priv(peer, (const char *) cookie_string, sizeof(pbc_cookie_data), 
                       &out, &outlen)) {
	libpbc_debug("libpbc_sign_bundle_cookie: libpbc_mk_priv failed");
	return NULL;
    }

    cookie = (unsigned char *) libpbc_alloc_init(4 * outlen / 3 + 20);
    if (!cookie) {
	libpbc_debug("libpbc_sign_bundle_cookie: libpbc_alloc_init failed");
	free(out);
	return NULL;
    }

    libpbc_base64_encode( (unsigned char *) out, cookie, outlen);
    free(out);

    return cookie;
}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
/* for now we use the last_ts field in login cookie as expire_ts */
/* this is the call used for creating G and S cookies            */
#ifdef APACHE
unsigned char *libpbc_get_cookie_p(pool *p, unsigned char *user, 
				   unsigned char type, 
				   unsigned char creds,
				   int pre_sess_token,
				   unsigned char *appsrvid,
				   unsigned char *appid,
				   const char *peer)
#else
unsigned char *libpbc_get_cookie_np(unsigned char *user, 
				    unsigned char type, 
				    unsigned char creds,
				    int pre_sess_token,
				    unsigned char *appsrvid,
				    unsigned char *appid,
				    const char *peer)
#endif
{

    return(libpbc_get_cookie_with_expire(user,
					 type,
					 creds,
				    	 pre_sess_token,
					 time(NULL),
					 appsrvid,
					 appid,
					 peer));

}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
/* for now we use the last_ts field in login cookie as expire_ts */
/* the overleading of last_ts with expire_ts is ugly but we're   */
/* going to reframe the library interfaces anyway and this will  */
/* be treated better then.                                       */
#ifdef APACHE
unsigned char *libpbc_get_cookie_with_expire_p(pool *p, unsigned char *user, 
					       unsigned char type, 
					       unsigned char creds,
					       int pre_sess_token,
					       time_t expire,
					       unsigned char *appsrvid,
					       unsigned char *appid,
					       const char *peer)
#else
unsigned char *libpbc_get_cookie_with_expire_np(unsigned char *user, 
						unsigned char type, 
						unsigned char creds,
						int pre_sess_token,
						time_t expire,
						unsigned char *appsrvid,
						unsigned char *appid,
						const char *peer)
#endif
{

    pbc_cookie_data 		*cookie_data;
    unsigned char			*cookie_string;
    unsigned char			*cookie;

    libpbc_augment_rand_state(user, PBC_USER_LEN);

    cookie_data = libpbc_init_cookie_data();
    libpbc_populate_cookie_data(cookie_data, user, type, creds, pre_sess_token, expire, appsrvid, appid);
    cookie_string = libpbc_stringify_cookie_data(cookie_data);
    pbc_free(cookie_data);
    cookie = libpbc_sign_bundle_cookie(cookie_string, peer);
    pbc_free(cookie_string);

    return cookie;
}

/*                                                                            */
/*  deal with unbundling a cookie                                             */
/*                                                                            */
#ifdef APACHE
pbc_cookie_data *libpbc_unbundle_cookie_p(pool *p, char *in, 
					  const char *peer)
#else
pbc_cookie_data *libpbc_unbundle_cookie_np(char *in, 
					   const char *peer)
#endif
{
    pbc_cookie_data	*cookie_data;
    char *plain;
    int plainlen;
    int outlen;
    unsigned char buf[PBC_4K];

    /* libpbc_debug("libpbc_unbundle_cookie: hello\n"); */

    memset(buf, 0, sizeof(buf));

    if ( strlen(in) < PBC_SIG_LEN || strlen(in) > PBC_4K ) {
        libpbc_debug("libpbc_unbundle_cookie: malformed cookie %s\n", in);
        return 0;
    }

    if( ! libpbc_base64_decode((unsigned char *)in, buf, &outlen) ) {
        libpbc_debug("libpbc_unbundle_cookie: could not base64 decode cookie.\n");
        return 0;
    }

    if (libpbc_rd_priv(peer, (const char *) buf, outlen, &plain, &plainlen)) {
        libpbc_debug("libpbc_unbundle_cookie: libpbc_rd_priv() failed\n");
        return 0;
    }

    if (plainlen != sizeof(pbc_cookie_data)) {
        libpbc_debug("libpbc_unbundle_cookie: cookie wrong size: %d != %d\n",
                     plainlen, sizeof(pbc_cookie_data) + PBC_SIG_LEN);
        return 0;
    }

    /* copy it into a pbc_cookie_data struct */
    cookie_data = (pbc_cookie_data *) malloc(sizeof(pbc_cookie_data));
    if (!cookie_data) {
        libpbc_debug("libpbc_unbundle_cookie: malloc() failed");
        free(plain);
        return 0;
    }
    memcpy((*cookie_data).string, plain, sizeof(pbc_cookie_data));
    free(plain);

    cookie_data = libpbc_destringify_cookie_data(cookie_data);

    (*cookie_data).broken.last_ts = ntohl((*cookie_data).broken.last_ts);
    (*cookie_data).broken.create_ts = ntohl((*cookie_data).broken.create_ts);
    (*cookie_data).broken.pre_sess_token = ntohl((*cookie_data).broken.pre_sess_token);

    return cookie_data;
}
    
/*                                                                            */
/*  update last_ts in cookie                                                  */
/*                                                                            */
/* takes a cookie_data structure, updates the time, signs and packages up     */
/* the cookie to be sent back into the world                                  */
/*                                                                            */
#ifdef APACHE
unsigned char *libpbc_update_lastts_p(pool *p, pbc_cookie_data *cookie_data,
				      const char *peer)
#else
unsigned char *libpbc_update_lastts_np(pbc_cookie_data *cookie_data,
				       const char *peer)
#endif
{
    unsigned char	*cookie_string;
    unsigned char	*cookie;

    (*cookie_data).broken.last_ts = time(NULL);
    cookie_string = libpbc_stringify_cookie_data(cookie_data);
    cookie = libpbc_sign_bundle_cookie(cookie_string, peer);
    /* xxx memory leaks? */

    return cookie;

}

/*                                                                            */
/* check version string in cookie                                             */
/*                                                                            */
int libpbc_check_version(pbc_cookie_data *cookie_data)
{
    unsigned char *a = (*cookie_data).broken.version;
    unsigned char *b = (unsigned char *) PBC_VERSION;

    if( a[0] == b[0] && a[1] == b[1] )
        return(PBC_OK);
    if( a[0] == b[0] && a[1] != b[1] ) {
        libpbc_debug("Minor version mismatch cookie: %s version: %s\n", a, b);
        return(PBC_OK);
    }

    return(PBC_FAIL);

}

/** 
 * check to see if whatever has timed out
 * @param fromc time to be checked, format unix time
 * @param exp number of seconds for timeout
 * @returns PBC_OK if not expired, PBC_FAIL if expired
 */
int libpbc_check_exp(time_t fromc, int exp)
{
    if( (fromc + exp) > time(NULL) )
        return PBC_OK;
    else 
        return PBC_FAIL;

}

/** 
 * use openssl calls to get a random int
 * @returns random int or -1 for error
 */
int libpbc_random_int()
{
    unsigned char 	buf[16];
    int 		i;
    unsigned long 	err;


    if( RAND_bytes(buf, sizeof(int)) == 0 ) {
        while( (err=ERR_get_error()) )
            pbc_log_activity(PBC_LOG_ERROR, 
            		"OpenSSL error getting random bytes: %lu", err);
        return(-1);
    }

    bcopy(&buf, &i, sizeof(int));
    return(i);

}

/** 
 * something that should never be executed, but shuts-up the compiler warning
 */
void libpbc_dummy()
{
    char c;

    c=*(redirect_reason[0]);

}


