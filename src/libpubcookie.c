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
    $Id: libpubcookie.c,v 2.50 2003-03-06 06:12:50 jjminer Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#if defined (WIN32)

# include <windows.h>
typedef  int pid_t;  /* win32 process ID */
# include <process.h>  /* getpid */
#include  <io.h>
#include  <stdio.h>

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

# ifdef HAVE_TIME_H
#  include <time.h>
# endif /* HAVE_TIME_H */

# ifdef HAVE_STRING_H
#  include <string.h>
# endif /* HAVE_STRING_H */

# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif /* HAVE_STRINGS_S */

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

#if defined (APACHE1_3)
# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"
#else
typedef void pool;
#endif

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

#ifdef HAVE_DMALLOC_H
# ifndef APACHE
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

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

const char *get_my_hostname(pool *p)
{
    return libpbc_get_cryptname(p);
}

/** 
 * find the credential id value for an authtype name
 * @param name the name of the authtype
 * @returns either PBC_CREDS_NONE or the credential id to pass in the cookie
 */
const char libpbc_get_credential_id(pool *p, const char *name)
{
    if (!strcasecmp(name, "uwnetid")) {
         pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "WARNING: AuthType %s will not be supported in future versions - user AuthType WebISO\n", name);
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
static void print_hex_nybble(pool *p, FILE *f,int n)
{
  char *hex="0123456789abcdef";
  n&=0x0f;
  fputc(hex[n],f);
}

static void print_hex_bytes(pool *p, FILE *f,void *s_in,int len)
{
  unsigned char *s=(unsigned char *)s_in;
  fprintf(f,"[%lx]",(long)s);
  if(s==0) {
    fprintf(f,"(null)");
    return;
  }
  while(len-->0) {
    print_hex_nybble(p, f,(*s)>>4);
    print_hex_nybble(p, f,(*s));
    s++;
  }
}

/* get a nice pretty log time                                                 */
char *libpbc_time_string(pool *p, time_t t)
{ 
    struct tm	*tm;
    static char	buf[PBC_1K];

    tm = localtime(&t);
    strftime(buf, sizeof(buf)-1, "%Y/%m/%d %H:%M:%S", tm);

    return buf;
}

/* when things fail too badly to go on ...                                    */
void *libpbc_abend(pool *p, const char *format,...)
{
    va_list args;
    
    va_start(args, format);
    pbc_vlog_activity(p, PBC_LOG_ERROR, format, args);
    va_end(args);

#if defined (WIN32)
    return NULL;
#else
    exit(EXIT_FAILURE);
#endif
}

void libpbc_void(pool *p, void *thing) {
}

void *malloc_debug(pool *p, size_t x) {
    void *ptr;
    ptr = pbc_malloc (p, x);
    pbc_log_activity(p, PBC_LOG_ERROR, "  pbc_malloc(p, %d)= x%X\n",x,ptr);
    return ptr;
}

void free_debug(pool *p, void *ptr) {
    pbc_log_activity(p, PBC_LOG_ERROR, "  pbc_free= x%X\n",ptr);
    pbc_free(p, ptr);
}

/* keep pumping stuff into the random state                                   */
void libpbc_augment_rand_state(pool *p, unsigned char *array, int len)
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

/*                                                                            */
/* any general startup stuff goes here                                        */
/*                                                                            */
void libpbc_pubcookie_init(pool *p)
{
    unsigned char	buf[sizeof(pid_t)];
    pid_t		pid;

    /*  pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_pubcookie_init\n"); */
    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    libpbc_augment_rand_state(p, buf, sizeof(pid));

    if (security_init(p)) {
        pbc_log_activity(p, PBC_LOG_ERROR, "security_init failed");
        exit(1);
    }

}

static void limit_strcpy(pool *p, char *dst, char *src, int siz)
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

/* mallocs a pbc_cookie_data struct                                           */
pbc_cookie_data *libpbc_init_cookie_data(pool *p)
{
    pbc_cookie_data *cookie_data;

    cookie_data=(pbc_cookie_data *)pbc_malloc(p, sizeof(pbc_cookie_data));
    memset(cookie_data, 0, sizeof(pbc_cookie_data));
    return cookie_data;
}

/*                                                                            */
unsigned char *libpbc_gethostip(pool *p)
{
    struct hostent      *h;
    unsigned char       *addr;

#if defined (WIN32)
    char                hostname[PBC_1K];
    int                 err;
    
    hostname[0] = '\0';
    err=gethostname(hostname, sizeof(hostname));
    if( (h = gethostbyname(hostname)) == NULL ) {
        libpbc_abend(p, "gethostname error= %d, %s: host unknown.\n", err,hostname);
	return NULL;
    }
#else
    struct utsname      myname;

    if ( uname(&myname) < 0 ) {
	libpbc_abend(p, "problem doing uname lookup\n");
	return NULL;
    }

    if ( (h = gethostbyname(myname.nodename)) == NULL ) {
       	libpbc_abend(p, "%s: host unknown.\n", myname.nodename);
	return NULL;
    }
#endif

    addr = pbc_malloc(p, h->h_length);
    memcpy(addr, h->h_addr_list[0], h->h_length);
    
    return addr;
}

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile(pool *p, const char *peername, char *buf)
{

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "make_crypt_keyfile: hello\n");

    strlcpy(buf, PBC_KEY_DIR, 1024);

    if (buf[strlen(buf)-1] != '/') {
        strlcat(buf, "/", 1024);
    }
    strlcat(buf, peername, 1024);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "make_crypt_keyfile: goodbye\n");
}

/**
 * generates a random key for peer and writes it to the disk
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_generate_crypt_key(pool *p, const char *peer)
{
    unsigned char buf[PBC_DES_KEY_BUF];
    char keyfile[1024];
    FILE *f;

    RAND_bytes(buf, PBC_DES_KEY_BUF);

    make_crypt_keyfile(p, peer, keyfile);
    if (!(f = pbc_fopen(p, keyfile, "w"))) {
        return PBC_FAIL;
    }
    fwrite(buf, sizeof(char), PBC_DES_KEY_BUF, f);
    pbc_fclose(p, f);

    return PBC_OK;
}

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the PB_C_DES_KEY_BUF-sized key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_set_crypt_key(pool *p, const char *key, const char *peer)
{
    char keyfile[1024];
    FILE *f;

    make_crypt_keyfile(p, peer, keyfile);
#ifdef WIN32
    if (!(f = pbc_fopen(p, keyfile, "wb"))) {
#else
    if (!(f = pbc_fopen(p, keyfile, "w"))) {
#endif
	return PBC_FAIL;
    }
    fwrite(key, sizeof(char), PBC_DES_KEY_BUF, f);
    pbc_fclose(p, f);

    return PBC_OK;
}

/*                                                                           */
int libpbc_get_crypt_key(pool *p, crypt_stuff *c_stuff, const char *peer)
{
    FILE             *fp;
    char             *key_in;
    char keyfile[1024];

/*  pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_get_crypt_key\n"); */

    make_crypt_keyfile(p, peer, keyfile);

    key_in = (char *)pbc_malloc(p, PBC_DES_KEY_BUF);

    if( ! (fp = pbc_fopen(p, keyfile, "rb")) ) { /* win32 - must be binary read */
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_get_crypt_key: Failed open: %s\n", keyfile);
        return PBC_FAIL;
    }
    
    if( fread(key_in, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_get_crypt_key: Failed read: %s\n", keyfile);
	pbc_fclose(p, fp);
	return PBC_FAIL;
    }
    
#ifdef DEBUG_ENCRYPT_COOKIE
    pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_get_crypt_key: reading crypt key '%s'\n", keyfile);
#endif

    pbc_fclose(p, fp);

    memcpy(c_stuff->key_a, key_in, sizeof(c_stuff->key_a));
    pbc_free(p, key_in);

    return PBC_OK;
}

unsigned char *libpbc_stringify_seg(pool *p, unsigned char *start, unsigned char *seg, unsigned len)
{
    int			seg_len;

    seg_len = ( len < strlen((const char *)seg) ) ? len : strlen((const char *)seg);
    memcpy(start, seg, seg_len);
    return start + len;
}

/*                                                                            */
pbc_cookie_data *libpbc_destringify_cookie_data(pool *p, pbc_cookie_data *cookie_data) 
{

    (*cookie_data).broken.user[PBC_USER_LEN-1] = '\0';
    (*cookie_data).broken.version[PBC_VER_LEN-1] = '\0';
    (*cookie_data).broken.appid[PBC_APP_ID_LEN-1] = '\0';
    (*cookie_data).broken.appsrvid[PBC_APPSRV_ID_LEN-1] = '\0';
    return cookie_data;

}

void print_cookie_string(pool *p, const char *prelude, char *cookie_string)
{
    unsigned char	printable[PBC_4K];
    int			i;

    memcpy(printable, cookie_string, sizeof(pbc_cookie_data));

    for( i=0; i<sizeof(pbc_cookie_data); i++ ) {
        if( printable[i] == '\0' )
            printable[i] = '-';

    }
    
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "%s %s", prelude, printable);

}

/* package the cookie info for transit                                        */
/*   - make the cookie_data struct a string                                   */
/*   - do network byte order conversion                                       */
unsigned char *libpbc_stringify_cookie_data(pool *p, pbc_cookie_data *cookie_data) 
{
    unsigned char	*cookie_string;
    unsigned char	*ptr;
    int			temp;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_stringify_cookie_data: hello, user: %s\n", (*cookie_data).broken.user);

    ptr = cookie_string = 
		(unsigned char *)pbc_malloc(p, sizeof(pbc_cookie_data));
    memset(cookie_string, 0, sizeof(pbc_cookie_data));

    ptr = libpbc_stringify_seg(p, ptr, (*cookie_data).broken.user, PBC_USER_LEN);
    ptr = libpbc_stringify_seg(p, ptr, (*cookie_data).broken.version, PBC_VER_LEN);
    ptr = libpbc_stringify_seg(p, ptr, (*cookie_data).broken.appsrvid, PBC_APPSRV_ID_LEN);
    ptr = libpbc_stringify_seg(p, ptr, (*cookie_data).broken.appid, PBC_APP_ID_LEN);
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
int libpbc_get_crypt_index(pool *p) 
{
    unsigned char	r_byte[1];
    int			index;

    r_byte[0] = '\0';
    while ( r_byte[0] == '\0' ) 
        RAND_bytes(r_byte, 1);
    index = (int)r_byte[0] - (int)r_byte[0]/PBC_DES_INDEX_FOLDER;
    return index;
}

/* put stuff in the cookie structure                                          */
/*  note: we don't do network byte order conversion here,                     */
/*  instead we leave that for stringify                                       */
/*                                                                            */
void libpbc_populate_cookie_data(pool *p, pbc_cookie_data *cookie_data,
	                  unsigned char *user, 
	                  unsigned char type, 
			  unsigned char creds,
			  int pre_sess_token,
                          time_t expire,
			  unsigned char *appsrvid,
			  unsigned char *appid) 
{

    /* pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_populate_cookie_data\n"); */

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
unsigned char *libpbc_sign_bundle_cookie(pool *p, unsigned char *cookie_string,
					    const char *peer)
{
    unsigned char		*cookie;
    char *out;
    int outlen;
    
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"libpbc_sign_bundle_cookie: hello\n");

    if (libpbc_mk_priv(p, peer, (const char *) cookie_string,
			sizeof(pbc_cookie_data), &out, &outlen)) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
		"libpbc_sign_bundle_cookie: libpbc_mk_priv failed\n");
        return NULL;
    }

    cookie = (unsigned char *) pbc_malloc(p, 4 * outlen / 3 + 20);
    if (!cookie) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
		"libpbc_sign_bundle_cookie: pbc_malloc failed\n");
        pbc_free(p, out);
        return NULL;
    }

    libpbc_base64_encode(p, (unsigned char *) out, cookie, outlen);
    pbc_free(p, out);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"libpbc_sign_bundle_cookie: goodbye\n");
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"libpbc_sign_bundle_cookie: cookie: %s\n", cookie);

    return cookie;
}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
/* for now we use the last_ts field in login cookie as expire_ts */
/* this is the call used for creating G and S cookies            */
unsigned char *libpbc_get_cookie(pool *p, unsigned char *user, 
				    unsigned char type, 
				    unsigned char creds,
				    int pre_sess_token,
				    unsigned char *appsrvid,
				    unsigned char *appid,
				    const char *peer)
{

    return(libpbc_get_cookie_with_expire(p, user,
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
unsigned char *libpbc_get_cookie_with_expire(pool *p, unsigned char *user, 
						unsigned char type, 
						unsigned char creds,
						int pre_sess_token,
						time_t expire,
						unsigned char *appsrvid,
						unsigned char *appid,
						const char *peer)
{

    pbc_cookie_data 		*cookie_data;
    unsigned char		*cookie_string;
    unsigned char		*cookie;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"libpbc_get_cookie_with_expire: hello\n");

    libpbc_augment_rand_state(p, user, PBC_USER_LEN);

    cookie_data = libpbc_init_cookie_data(p);
    libpbc_populate_cookie_data(p, cookie_data, user, type, creds, 
                                pre_sess_token, expire, appsrvid, appid);
    cookie_string = libpbc_stringify_cookie_data(p, cookie_data);
    pbc_free(p, cookie_data);

    cookie = libpbc_sign_bundle_cookie(p, cookie_string, peer);
    pbc_free(p, cookie_string);
    
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"libpbc_get_cookie_with_expire: goodbye\n");

    return cookie;
}

/*                                                                            */
/*  deal with unbundling a cookie                                             */
/*                                                                            */
pbc_cookie_data *libpbc_unbundle_cookie(pool *p, char *in, const char *peer)
{
    pbc_cookie_data	*cookie_data;
    char *plain;
    int plainlen;
    int outlen;
    unsigned char *buf = pbc_malloc(p, PBC_4K);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_unbundle_cookie: hello\n");

    memset(buf, 0, PBC_4K);

    if ( strlen(in) < sizeof(pbc_cookie_data) || strlen(in) > PBC_4K ) {
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_unbundle_cookie: malformed cookie %s\n", in);
        return 0;
    }

    if( ! libpbc_base64_decode(p, (unsigned char *)in, buf, &outlen) ) {
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_unbundle_cookie: could not base64 decode cookie.\n");
        return 0;
    }

    if (libpbc_rd_priv(p, peer, (const char *)buf, outlen, &plain, &plainlen)) {
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_unbundle_cookie: libpbc_rd_priv() failed\n");
        return 0;
    }

    if (plainlen != sizeof(pbc_cookie_data)) {
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_unbundle_cookie: cookie wrong size: %d != %d\n",
                     plainlen, sizeof(pbc_cookie_data));
        return 0;
    }

    /* copy it into a pbc_cookie_data struct */
    cookie_data = (pbc_cookie_data *) pbc_malloc(p, sizeof(pbc_cookie_data));
    if (!cookie_data) {
        pbc_log_activity(p, PBC_LOG_ERROR, "libpbc_unbundle_cookie: pbc_malloc(p, ) failed");
        pbc_free(p, plain);
        return 0;
    }
    memcpy((*cookie_data).string, plain, sizeof(pbc_cookie_data));
    pbc_free(p, plain);

    cookie_data = libpbc_destringify_cookie_data(p, cookie_data);

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
unsigned char *libpbc_update_lastts(pool *p, pbc_cookie_data *cookie_data,
				       const char *peer)
{
    unsigned char	*cookie_string;
    unsigned char	*cookie;

    (*cookie_data).broken.last_ts = time(NULL);
    cookie_string = libpbc_stringify_cookie_data(p, cookie_data);
    cookie = libpbc_sign_bundle_cookie(p, cookie_string, peer);
    /* xxx memory leaks? */

    return cookie;

}

/*                                                                            */
/* check version string in cookie                                             */
/*                                                                            */
int libpbc_check_version(pool *p, pbc_cookie_data *cookie_data)
{
    unsigned char *a = (*cookie_data).broken.version;
    unsigned char *b = (unsigned char *) PBC_VERSION;

    if( a[0] == b[0] && a[1] == b[1] )
        return(PBC_OK);
    if( a[0] == b[0] && a[1] != b[1] ) {
        pbc_log_activity(p, PBC_LOG_ERROR, "Minor version mismatch cookie: %s version: %s\n", a, b);
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
int libpbc_check_exp(pool *p, time_t fromc, int exp)
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
int libpbc_random_int(pool *p)
{
    unsigned char 	buf[16];
    int 		i;
    unsigned long 	err;


    if( RAND_bytes(buf, sizeof(int)) == 0 ) {
        while( (err=ERR_get_error()) )
            pbc_log_activity(p, PBC_LOG_ERROR, 
            		"OpenSSL error getting random bytes: %lu", err);
        return(-1);
    }

    bcopy(&buf, &i, sizeof(int));
    return(i);

}

/** 
 * something that should never be executed, but shuts-up the compiler warning
 */
void libpbc_dummy(pool *p)
{
    char c;

    c=*(redirect_reason[0]);

}


