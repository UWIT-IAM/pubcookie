
#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

/* openssl */
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

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef WIN32
# include <io.h>
# include <assert.h>
# define DIR_SEP "\\"
#else
# define DIR_SEP "/"
#endif

#include "pbc_config.h"
#include "pbc_logging.h"
#include "pbc_myconfig.h"
#include "libpubcookie.h"
#include "strlcpy.h"

#include "security.h"
#include "pubcookie.h"

#define PBC_SIG_LEN 128

/* privacy format is:

   outbuf = <sig> <crypted>
   crypted = <data> [index1 byte] [index2 byte]

   [index2 byte] is an offset into the shared secret which is XOR'd with
   PBC_INIT_IVEC to form the ivec

   [index1 byte] is an index into the shared secret which is taken as the
   DES key
   
 */

/* our private session keypair */
static EVP_PKEY *sess_key;
static X509 *sess_cert;
static EVP_PKEY *sess_pub;

/* the granting key & certificate */
static EVP_PKEY *g_key;
static X509 *g_cert;
static EVP_PKEY *g_pub;

/* my name */
static char *myname = NULL;

static char *mystrdup(const char *s)
{
    if (s) return strdup(s);
    else return NULL;
}

/* destructively returns the value of the CN */
static char *extract_cn(char *s)
{
    char *p;
    char *q;

    if (!s) return NULL;

    p = strstr(s, "CN=");
    if (p) {
        p += 3;
        q = strstr(p, "/Email=");
        if (q) {
            *q = '\0';
        }
    }

    return p;
}


/* find the keys that we'll be using, look for stuff in this order:
   . the SSL key/certificate
   . the pubcookie_session.{key,cert}
   . the pubcookie_login.{key,cert}.[hostname]
   . (generate them ourselves?)
   

   for the granting key/certificate:
   . check "granting_key_file", "granting_cert_file"
   . check pubcookie_granting

*/
int security_init(void)
{

    /* our private session keypair */
    char *keyfile = NULL;
    char *certfile = NULL;
    /* the granting key & certificate */
    char *g_keyfile;
    char *g_certfile;

    FILE *fp;

    /* first we try to use the ssl files */
    keyfile = mystrdup(libpbc_config_getstring("ssl_key_file", NULL));
    if (keyfile && access(keyfile, R_OK | F_OK)) {
	free(keyfile);
	/* not there ? */
	keyfile = NULL;
    }
    certfile = mystrdup(libpbc_config_getstring("ssl_cert_file", NULL));
    if (certfile && access(certfile, R_OK | F_OK)) {
	free(certfile);
	/* not there ? */
	certfile = NULL;
    }

    if (!keyfile && !certfile) {
	/* fall back to the pubcookie_session files */
	keyfile = malloc(1025);
	snprintf(keyfile, 1024, "%s"DIR_SEP"%s", PBC_KEY_DIR,
		 "pubcookie_session.key");

	certfile = malloc(1025);
	snprintf(certfile, 1024, "%s"DIR_SEP"%s", PBC_KEY_DIR,
		 "pubcookie_session.cert");

	if (access(keyfile, R_OK | F_OK) || access(certfile, R_OK | F_OK)) {
	    /* session keys not valid */
	    free(keyfile);
	    free(certfile);
	    keyfile = NULL;
	    certfile = NULL;
	}
    }

    if (!keyfile && !certfile) {
	/* try the pubcookie_login files */
	keyfile = malloc(1025); /* Windows snprintf broken 8/21/02 RJC */
	snprintf(keyfile, 1024, "%s"DIR_SEP"%s", PBC_KEY_DIR,
		 "pubcookie_login.key");

	certfile = malloc(1025); /* Windows snprintf broken 8/21/02 RJC */
	snprintf(certfile, 1024, "%s"DIR_SEP"%s", PBC_KEY_DIR,
		 "pubcookie_login.cert");

	if (access(keyfile, R_OK | F_OK) || access(certfile, R_OK | F_OK)) {
	    /* login keys not valid */
 	    free(keyfile);
	    free(certfile);
	    keyfile = NULL;
	    certfile = NULL;
	}
    }

    if (!keyfile) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't find session keyfile (try setting ssl_key_file?)");
	return -1;
    }

    if (!certfile) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't find session certfile (try setting ssl_cert_file?)");
	return -1;
    }

    /* it's generally easier to find the granting key/cert */
    g_keyfile = mystrdup(libpbc_config_getstring("granting_key_file", NULL));
    g_certfile = mystrdup(libpbc_config_getstring("granting_cert_file", NULL));


    if (!g_keyfile) {
	g_keyfile = malloc(1025); /* Windows snprintf broken  8/21/02 RJC */
	snprintf(g_keyfile, 1024, "%s"DIR_SEP"%s", PBC_KEY_DIR,
		 "pubcookie_granting.key");
    }

    if (!g_certfile) {
	g_certfile = malloc(1025); /* Windows snprintf broken 8/21/02 RJC */
	snprintf(g_certfile, 1024, "%s"DIR_SEP"%s", PBC_KEY_DIR,
		 "pubcookie_granting.cert");
    }
    /* test g_keyfile */
    if (access(g_keyfile, R_OK | F_OK)) {
        /* this is only a problem for login servers */
	pbc_log_activity(PBC_LOG_DEBUG_VERBOSE,
                         "couldn't find granting keyfile (try setting granting_key_file?)");
	g_keyfile = NULL;
    }

    /* test g_certfile; it's a fatal error if this isn't found */
    if (access(g_certfile, R_OK | F_OK)) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't find granting certfile (try setting granting_cert_file?): tried %s", g_certfile);
	return -1;
    }

    /* now read them into memory */
	
    /* session key */

    fp = fopen(keyfile, "r");

    if (!fp) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't read keyfile: fopen %s: %m", keyfile);
	return -1;
    }

    sess_key = (EVP_PKEY *) PEM_ASN1_read((char *(*)())d2i_PrivateKey, 
					  PEM_STRING_EVP_PKEY,
					  fp, NULL, NULL, NULL);
    if (!sess_key) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't parse session key: %s", keyfile);
	return -1;
    }
    fclose(fp);

    /* session cert */
    fp = fopen(certfile, "r");
    if (!fp) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't read certfile: fopen %s: %m", certfile);
	return -1;
    }
    sess_cert = (X509 *) PEM_ASN1_read((char *(*)()) d2i_X509,
				       PEM_STRING_X509,
				       fp, NULL, NULL, NULL);
    if (!sess_cert) {
	/* xxx openssl errors */
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't parse session certificate: %s", certfile);
	return -1;
    }
    sess_pub = X509_extract_key(sess_cert);
    myname = X509_NAME_oneline (X509_get_subject_name (sess_cert),0,0);
    myname = extract_cn(myname);
    if (!myname) {
        char tmp[1024];
        /* hmm, no name encoded in the certificate; we'll just use our
           hostname */
        gethostname(tmp, sizeof(tmp)-1);
        myname = strdup(tmp);
    }
    fclose(fp);

    /* granting key */
    if (g_keyfile) {
	fp = fopen(g_keyfile, "r");

	if (fp) {
	    g_key = (EVP_PKEY *) PEM_ASN1_read((char *(*)()) d2i_PrivateKey, 
					       PEM_STRING_EVP_PKEY,
					       fp, NULL, NULL, NULL);
	    if (!g_key) {
		pbc_log_activity(PBC_LOG_ERROR, 
                                 "couldn't parse granting key: %s", g_keyfile);
		return -1;
	    }
	    fclose(fp);
	} else {
	    pbc_log_activity(PBC_LOG_ERROR, 
                             "couldn't read granting keyfile: fopen %s: %m", 
                             g_keyfile);  /* Bugfix 8/21/02 RJC */
	    /* fatal, since we were configured for it */
	    exit(1);
	}
    }
    /* granting cert */
    fp = fopen(g_certfile, "r");
    if (!fp) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't read granting certfile: fopen %s: %m", 
                         g_certfile); /* Bugfix 8/21/02 RJC */
	return -1;
    }
    g_cert = (X509 *) PEM_ASN1_read((char *(*)()) d2i_X509,
				    PEM_STRING_X509,
				    fp, NULL, NULL, NULL);
    if (!g_cert) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't parse granting certificate: %s", g_certfile);
	return -1;
    }
    g_pub = X509_extract_key(g_cert);

    fclose(fp);

    /* xxx CA file / CA dir ? */

    /* initialize the random number generator */
#if defined (WIN32)
    /* Windows only has milliseconds */
    {
	SYSTEMTIME   ts;
	unsigned char buf[sizeof(ts.wMilliseconds)];
	
	GetLocalTime(&ts);
	memcpy(buf, &ts.wMilliseconds, sizeof(ts.wMilliseconds));
	RAND_seed(buf, sizeof(ts.wMilliseconds));
    }
#else
    {
	struct timeval tv; 
	struct timezone tz;
	unsigned char buf[sizeof(tv.tv_usec)];
	
	gettimeofday(&tv, &tz);
	memcpy(buf, &tv.tv_usec, sizeof(tv.tv_usec));
	RAND_seed(buf, sizeof(tv.tv_usec));
    }
#endif

    return 0;
}

const char *libpbc_get_cryptname(void)
{
    return myname;
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

static int get_crypt_key(const char *peername, char *buf)
{
    FILE *fp;
    char keyfile[1024];

    make_crypt_keyfile(peername, keyfile);
	
    if (!(fp = fopen(keyfile, "rb"))) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "can't open crypt key %s: %m", keyfile);
	return -1;
    }

    if( fread(buf, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "canb't read crypt key %s: short read", keyfile);
	fclose(fp);
	return -1;
    }

    fclose(fp);

    return 0;
}

/**
 * libpbc_mk_priv takes 'buf', 'len', and returns 'outbuf', 'outlen',
 * an encrypted string that can only be read by 'peer'.
 * @param peer the name of the peer this is destined for.  if NULL,
 * the message will be signed with private material that is only known
 * to this host. 
 * @param buf a pointer to the cleartext string
 * @param len the length of the data pointed to by buf
 * @param outbuf will be filled in with a malloc()ed buffer.  it must
 * later be free()ed.
 * @param outlen the length of outbuf.
 * @returns 0 on success, non-zero on failure.
 */
int libpbc_mk_priv(const char *peer, const char *buf, const int len,
		   char **outbuf, int *outlen)
{
    int r;
    int index1, index2;
    unsigned char r_byte;
    int i = 0;
    des_cblock key, ivec;
    des_key_schedule ks;
    unsigned char keybuf[PBC_DES_KEY_BUF];
    static unsigned char ivec_tmp[PBC_INIT_IVEC_LEN] = PBC_INIT_IVEC;
    const char *peer2;
    char *mysig = NULL;
    int siglen;
    int tries = 5;
    int c;

    assert(outbuf != NULL && outlen != NULL);
    assert(buf != NULL && len > 0);

    peer2 = peer ? peer : libpbc_get_cryptname();
    if (get_crypt_key(peer2, (char *) keybuf) < 0) {
        pbc_log_activity(PBC_LOG_ERROR, 
                         "get_crypt_key(%s) failed", peer2);
	return -1;
    }

    memset(key, 0, sizeof(key));
    des_set_odd_parity(&key);
    while (des_set_key_checked(&key, ks) < 0 && --tries) {
	r_byte = 0;	/* why isn't 0 allowed? */
	while (r_byte == 0) RAND_bytes(&r_byte, 1);
	index1 = r_byte;

	memcpy(key, &(keybuf[index1]), sizeof(key));
        des_set_odd_parity(&key);
    }
    if (!tries) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't find a good DES key");
	return -1;
    }

    r_byte = 0;    /* why isn't 0 allowed? */
    while (r_byte == 0) RAND_bytes(&r_byte, 1);
    index2 = r_byte;

    /* setup ivec */
    memcpy(ivec, &keybuf[index2], sizeof(ivec));
    for (c = 0; c < sizeof(ivec); ++c) {
	ivec[c] ^= ivec_tmp[i % sizeof(ivec_tmp)];
    }

    r = libpbc_mk_safe(peer, buf, len, &mysig, &siglen);
    if (!r) {
        *outlen = len + siglen + 2;
        *outbuf = malloc(*outlen);
        if (!*outbuf) {
            pbc_log_activity(PBC_LOG_ERROR, 
                             "libpbc_mk_priv: malloc failed");
            free(mysig);
            return -1;
        }

	des_cfb64_encrypt( (unsigned char *) mysig, (unsigned char *) *outbuf, 
                           siglen, ks, &ivec, &i, DES_ENCRYPT);
	free(mysig);

	des_cfb64_encrypt( (unsigned char *) buf, 
                       (unsigned char *) (*outbuf) + siglen, len, 
                       ks, &ivec, &i, DES_ENCRYPT);
	(*outbuf)[siglen + len] = (unsigned char) index1;
	(*outbuf)[siglen + len + 1] = (unsigned char) index2;
    }

    if (r) {
        pbc_log_activity(PBC_LOG_ERROR, 
                         "libpbc_mk_safe() failed");
	free(*outbuf);
	*outbuf = NULL;
    }

    return r;
}

/**
 * libpbc_rd_priv decodes an encrypted string sent by 'peer'.  if
 * 'peer' is NULL, we assume that this host previously called libpbc_mk_priv
 * @param peer the peer this message is destined to (the first parameter to
 * libpbc_mk_priv()).
 * @param buf a pointer to the encrypted message
 * @param len the length of the encrypted message
 * @param outbuf a malloc()ed pointer to the plaintext message
 * @param outlen the length of the plaintext message
 * @returns 0 on success, non-0 on failure (including if the message could 
 * not be decrypted or did not pass integrity checks
 */
int libpbc_rd_priv(const char *peer, const char *buf, const int len,
		   char **outbuf, int *outlen)
{
    int index1, index2;
    int i = 0;
    des_cblock key, ivec;
    des_key_schedule ks;
    unsigned char keybuf[PBC_DES_KEY_BUF];
    char mysig[PBC_SIG_LEN];
    static unsigned char ivec_tmp[PBC_INIT_IVEC_LEN] = PBC_INIT_IVEC;
    int c;
    int r;

    if (len < PBC_SIG_LEN + 2) {
        pbc_log_activity(PBC_LOG_ERROR, 
                         "libpbc_rd_priv() called with small length: %d", len);
        return -1;
    }

    /* since i'm reading a message, i always decrypt using my key in this
       security model. */
    if (get_crypt_key(libpbc_get_cryptname(), (char *) keybuf) < 0) {
        return -1;
    }

    index1 = (unsigned char) buf[len - 2];
    index2 = (unsigned char) buf[len - 1];

    /* setup ivec */
    memcpy(ivec, &(keybuf[index2]), sizeof(ivec));
    for (c = 0; c < sizeof(ivec); ++c) {
        ivec[c] ^= ivec_tmp[i % sizeof(ivec_tmp)];
    }

    /* setup key */
    memcpy(key, &keybuf[index1], sizeof(key));
    des_set_odd_parity(&key);
    if (des_set_key_checked(&key, ks)) {
        pbc_log_activity(PBC_LOG_ERROR, 
                         "des_set_key_checked failed: didn't derive a good key");
        return -1;
    }

    /* allocate outbuf */
    *outlen = len - PBC_SIG_LEN - 2;
    *outbuf = (char *) malloc(*outlen);

    /* decrypt */
    des_cfb64_encrypt( (unsigned char *) buf,  (unsigned char *) mysig,
                       PBC_SIG_LEN, ks, &ivec, &i, DES_DECRYPT);

    des_cfb64_encrypt( (unsigned char *) buf + PBC_SIG_LEN,  
                       (unsigned char *) *outbuf, *outlen, ks, &ivec, &i,
                       DES_DECRYPT);

    /* verify signature */
    r = libpbc_rd_safe(peer, *outbuf, *outlen, mysig, PBC_SIG_LEN);

    if (r) {
        pbc_log_activity(PBC_LOG_ERROR, 
                         "plaintext received was %s", *outbuf);
        free(*outbuf);
        *outbuf = 0;
    }

    return r;
}

/**
 * libpbc_mk_safe allocates a signature and returns it to the
 * application. 'outbuf' does not contain the plaintext message; both
 * 'buf' and 'outbuf' must be sent to the other side
 */
int libpbc_mk_safe(const char *peer, const char *buf, const int len,
		   char **outbuf, int *outlen)
{
    unsigned char *sig;
    unsigned int sig_len = 0;
    EVP_MD_CTX ctx;
    EVP_PKEY *thekey;
    int r;

    assert(buf != NULL);
    assert(outbuf != NULL);
    assert(outlen != NULL);
    *outbuf = NULL;
    *outlen = 0;

    if (peer && !g_key) {
	pbc_log_activity(PBC_LOG_ERROR, 
                         "no granting key: can't secure message to %s", peer);
	return -1;
    }

    /* sign with g_key if there's a peer; key otherwise */
    if (peer) thekey = g_key;
    else thekey = sess_key;

    sig = (unsigned char *) malloc(EVP_PKEY_size(thekey));
    sig_len = EVP_PKEY_size(thekey);

    EVP_SignInit(&ctx, EVP_md5());
    EVP_SignUpdate(&ctx, buf, len);
    if (EVP_SignFinal(&ctx, sig, &sig_len, thekey)) {
	*outbuf = (char *) sig;
	*outlen = sig_len;
	r = 0;
    } else {
	/* xxx log openssl error */
	pbc_log_activity(PBC_LOG_ERROR, 
                         "EVP_SignFinal failed");
        free(sig);
	r = -1;
    }

    return r;
}

int libpbc_rd_safe(const char *peer, const char *buf, const int len,
		   const char *sigbuf, const int siglen)
{
    EVP_MD_CTX ctx;
    int r;

    assert(buf != NULL && sigbuf != NULL);

    /* if peer is set, we'll assume that this is signed with the granting
       key (no other cross-server messages in this security model) */

    /* initialize the MD5 context */
    EVP_VerifyInit(&ctx, EVP_md5());
    EVP_VerifyUpdate(&ctx, buf, len);
    r = EVP_VerifyFinal(&ctx, (unsigned char *) sigbuf, siglen, 
			peer ? g_pub : sess_pub);

    if (!r) {
	/* xxx log openssl error */
        ERR_load_crypto_strings();
        pbc_log_activity(PBC_LOG_ERROR, 
                         "couldn't verify signature for %s OpenSSL error: %s", 
                         peer ? peer : "(self)",
                         ERR_error_string(ERR_get_error(), NULL));
    }

    return !r;
}

