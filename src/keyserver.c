/*
    Copyright 2002 Carnegie Mellon University
     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|

    Comments and suggestions:
        Internal to U. of Washington: pubcookie@cac.washington.edu
        External to U. of Washington: pubcookie-ext@cac.washington.edu
    Pubcookie on the Web: http://www.pubcookie.org/

    a simple program for maintaining keys on the login server 
    
    by default, it should be invoked from inetd and acts vaguely like
    an HTTP server
 */
/*
    $Id: keyserver.c,v 2.2 2002-06-07 17:40:21 greenfld Exp $
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>

#ifndef KEYSERVER_CGIC
#include <getopt.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#else
#include <cgic.h>
#endif

#include "pbc_config.h"
#include "libpubcookie.h"

#ifndef KEYSERVER_CGIC
static SSL *ssl = NULL;

/**
 * log all outstanding errors from OpenSSL, attributing them to 'func'
 * @param func the function to attribute errors to
 */
static const char *logerrstr(const char *func)
{
    unsigned long r;

    while (r = ERR_get_error()) {
	syslog(LOG_ERR, "%s: %s", func, ERR_error_string(r, NULL));
    }
}

void myprintf(const char *format, ...)
{
    va_list args;
    char buf[4 * PBC_DES_KEY_BUF];

    assert(ssl != NULL);

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (SSL_write(ssl, buf, strlen(buf)) < 0) {
	logerrstr("SSL_write");
	exit(1);
    }
}
#else
void myprintf(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#endif


int debug = 1;
const char *keyfile = "server.pem";

enum optype {
    NOOP,
    GENKEY,
    SETKEY,
    FETCHKEY
};

/**
 * iterate through the 'login_servers' configuration variable, contacting
 * each one and setting my copy of peer's key on it
 */
void pushkey(const char *peer)
{
    char **lservers = libpbc_config_getlist("login_servers");
    char hostname[1024];
    int x;
    int res;

    if (!lservers) {
	/* only me here */
	return;
    }

    if (gethostname(hostname, sizeof(hostname)) < 0) {
	syslog(LOG_ERR, "gethostname(): %m");
	perror("gethostname");
	exit(1);
    }

    x = 0;
    for (x = 0; lservers[x] != NULL; x++) {
	if (!strcasecmp(hostname, lservers[x])) {
	    /* don't push the key to myself */
	    continue;
	}

	syslog(LOG_INFO, "setting %s's key on %s", peer, lservers[x]);

	res = fork();
	if (res < 0) {
	    syslog(LOG_ERR, "fork(): %m");
	    perror("fork");
	    exit(1);
	}
	if (fork() == 0) {
	    /* child */
	    res = execl("keyclient", "keyclient", 
			"-L", lservers[x],
			"-c", keyfile, 
			"-u", "-h", peer, NULL);
	    syslog(LOG_ERR, "execl(): %m");
	    exit(2);
	}
	
	/* parent */
	res = wait(&res);
	syslog(LOG_INFO, "setting %s's key on %s: %s", peer, lservers[x], 
	       res == 0 ? "done" : "error");
    }

    free(lservers);
}

/**
 * do the keyserver operation
 * @param peer the name of the client that's connected to us
 * @param op the operation to perform, one of GENKEY, SETKEY, FETCHKEY
 * @param newkey if the operation is SETKEY, "peer;base64(key)"
 * @return 0 on success, non-zero on error
 */
int doit(const char *peer, enum optype op, const char *newkey)
{
    char buf[4 * PBC_DES_KEY_BUF];
    crypt_stuff c_stuff;

    /* no HTML headers for me */
    myprintf("\r\n");

    switch (op) {
    case GENKEY:
    {
	/* 'peer' has asked us to generate a new key */
	assert(newkey == NULL);
	if (libpbc_generate_crypt_key(peer) < 0) {
	    myprintf("NO generate_new_key() failed\r\n");
	    syslog(LOG_ERR, "generate_new_key() failed");

	    return(1);
	}
	
	/* push the new key to the other login servers */
	pushkey(peer);

	break;
    }

    case SETKEY:
    {
	char *thekey, *thepeer;

	/* someone has asked us to set a key */

	/* verify that 'peer' is a fellow login server */
	if (strcasecmp(peer, PBC_LOGIN_HOST)) {
	    syslog(LOG_ERR, "%s attempted to set a key!\n", peer);
	    myprintf("NO you are not authorized to set keys\r\n");
	    return (1);
	}

	/* find <peer>;<key> */
	thepeer = strdup(newkey);
	thekey = strchr(thepeer, ';');
	if (!thekey) {
	    myprintf("NO bad form for new key\r\n");
	    /* xxx log */
	    return(1);
	}
	*thekey++ = '\0';
	
	/* xxx base64 decode thekey */

	/* go ahead and write it to disk */
	if (libpbc_set_crypt_key(thekey, thepeer) != PBC_OK) {
	    myprintf("NO couldn't set key\r\n");
	    /* xxx log */
	    return(1);
	}

	myprintf("OK key set\r\n");
	break;
    }

    case FETCHKEY:
	/* noop; we always return the new key */
	assert(newkey == NULL);
	break;
    }

    /* return the key */
    if (libpbc_get_crypt_key(&c_stuff, peer) != PBC_OK) {
	myprintf("NO couldn't retrieve key\r\n");
	return 1;
    }

    /* now give the key back to the application */
    libpbc_base64_encode(c_stuff.key_a, buf, PBC_DES_KEY_BUF);

    myprintf("OK %s\r\n", buf);
    fflush(stdout);
    
    return 0;
}

#ifndef KEYSERVER_CGIC

void usage(void)
{
    printf("usage: keyserver [options]\n");
    printf("  -c <key/cert file> : key to use for TLS authentication\n");
    printf("  -a                 : expect keyfile in ASN.1\n");
    printf("  -p (default)       : expect keyfile in PEM\n");
    printf("  -C <cert file>     : CA cert to use for client verification\n");
    printf("  -D <ca dir>        : directory of trusted CAs, hashed OpenSSL-style\n");
}

static int verify_callback(int ok, X509_STORE_CTX * ctx)
{
    X509   *err_cert;
    int     err;

    syslog(LOG_DEBUG, "verifying peer certificate... ok=%d", ok);

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);

    if (!ok) {
	syslog(LOG_ERR, "verify error:num=%d:%s", err,
	       X509_verify_cert_error_string(err));

	/* we want to ignore any key usage problems but no other faults */
	switch (ctx->error) {
	case X509_V_ERR_INVALID_PURPOSE:
	    syslog(LOG_ERR, "invalid purpose; ignoring error!");
	    ok = 1;
	    break;
	    
	default:
	    break;
	}
    }

    return ok;
}

/* run as if invoked by inetd */
int main(int argc, char *argv[])
{
    int c;
    int filetype = SSL_FILETYPE_PEM;
    const char *cafile = NULL;
    const char *cadir = NULL;
    char *peer = NULL;
    char *p;
    char buf[2048];
    enum optype op = NOOP;
    char *setkey = NULL;
    SSL_CTX *ctx;
    X509 *client_cert;
    int r;

    while ((c = getopt(argc, argv, "apc:ndh:C:D:")) != -1) {
	switch (c) {
	case 'a':
	    filetype = SSL_FILETYPE_ASN1;
	    break;

	case 'p':
	    filetype = SSL_FILETYPE_PEM;
	    break;

	case 'c':
	    /* 'optarg' is the key/certificate file */
	    keyfile = strdup(optarg);
	    break;

	case 'C':
	    /* 'optarg' is the CA we accept */
	    cafile = strdup(optarg);
	    break;

	case 'D':
	    /* 'optarg' is a directory of CAs */
	    cadir = strdup(optarg);
	    break;

	case '?':
	default:
	    usage();
	    break;
	}
    }

    /* xxx log connection information */


    /* initialize the OpenSSL connection */
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLSv1_server_method());

    /* setup the correct certificate */
    if (!SSL_CTX_use_certificate_file(ctx, keyfile, filetype)) {
	logerrstr("SSL_CTX_use_certificate_file");
	exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(ctx, keyfile, filetype)) {
	logerrstr("SSL_CTX_use_PrivateKey_file");
	exit(1);
    }
    if (!SSL_CTX_load_verify_locations(ctx, cafile, cadir)) {
	logerrstr("SSL_CTX_load_verify_locations");
	exit(1);
    }

    SSL_CTX_set_verify(ctx, 
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		       | SSL_VERIFY_CLIENT_ONCE, verify_callback);

    ssl = SSL_new(ctx);

    /* negotiate SSL */
    SSL_set_rfd(ssl, 0);
    SSL_set_wfd(ssl, 1);
    SSL_set_accept_state(ssl);

    if (SSL_accept(ssl) <= 0) {
	logerrstr("SSL_accept");
	ERR_print_errors_fp(stderr);
	exit(1);
    }

    /* check certificate */
    client_cert = SSL_get_peer_certificate (ssl);
    if (client_cert == NULL) {
	syslog(LOG_ERR, "client_cert == NULL???");
	exit(1);
    }

    peer = X509_NAME_oneline (X509_get_subject_name (client_cert),0,0);
    if (peer == NULL) {
	syslog(LOG_ERR, "peer == NULL???");
	exit(1);
    }
    if (strstr(peer, "CN=")) {
	peer = strstr(peer, "CN=");
	peer += 3;
    }
    syslog(LOG_INFO, "peer identified as %s\n", peer);

    /* read HTTP query */
    if (SSL_read(ssl, buf, sizeof(buf)) <= 0) {
	syslog(LOG_ERR, "SSL_read() failed");
	ERR_print_errors_fp(stderr);
	exit(1);
    }

    for (p = buf; *p != '\0'; p++) {
	/* look for 'genkey' */
	if (*p == '?' && !strncmp(p+1, "genkey=yes", 10)) {
	    op = GENKEY;
	}

	else if (*p == '?' && !strncmp(p+1, "genkey=no", 9)) {
	    op = FETCHKEY;
	}

	else if (*p == '?' && !strncmp(p+1, "genkey=put", 10)) {
	    op = SETKEY;
	}

	/* look for 'setkey' */
	else if (*p == '?' && !strncmp(p+1, "setkey", 7)) {
	    char *q;

	    p++; /* ? */
	    p += 7; /* setkey= */

	    setkey = strdup(p);
	    /* terminated by ? or ' ' */
	    q = strchr(setkey, '?');
	    if (q) *q = '\0';
	    q = strchr(setkey, ' ');
	    if (q) *q = '\0';
	}
    }

    if (op == NOOP) {
	syslog(LOG_ERR, "peer didn't specify an operation");
	exit(1);
    }

    /* call doit */
    r = doit(peer, op, setkey);
    SSL_shutdown(ssl);

    return r;
}

#else
/*
  this CGI requires client-side SSL authentication.
  make sure Apache is configured thusly in the SSL section:
  
  SSLVerifyClient optional
  SSLOptions +StdEnvVars

*/

/* run as if invoked as a CGI from Apache or another web server */

/**
 * cgiMain() is called per-connection
 */
int cgiMain() 
{
    const char *peer;
    char buf[2048];

    if (debug) {
	fprintf(stderr, "cgiMain: keyserver built on " __DATE__ " " __TIME__ "\n");
    }

    /* xxx log connection */

    libpbc_config_init(NULL, "keyserver");

    if (!getenv("HTTPS") || strcmp( getenv("HTTPS"), "on") ) {
	printf("\r\nNO HTTPS required\r\n");
	fprintf(stderr, "keyserver invoked without HTTPS\n");
	exit(1);
    }

    peer = getenv("SSL_CLIENT_S_DN_CN");
    if (!peer) {
	printf("\r\nNO REMOTE_USER not found\r\n");
	fprintf(stderr, "keyserver invoked without REMOTE_USER\n");
	exit(1);
    }
    if (debug) {
	fprintf(stderr, "peer identified as %s\n", peer);
    }

    buf[0] = '\0';

    /* find out what sort of request this is */
    if (cgiFormString("genkey", buf, sizeof(buf)-1) != cgiFormSuccess) {
	printf("\r\nNO bad genkey parameter\r\n");
	fprintf(stderr, "keyserver invoked with bad params\n");
	exit(1);
    }

    if (!strcmp(buf, "yes")) {
	if (debug) {
	    fprintf(stderr, "peer requested a new key\n");
	}
	doit(peer, GENKEY, NULL);
    }
    else if (!strcmp(buf, "put")) {
	if (debug) {
	    fprintf(stderr, "peer requested me to set a key\n");
	}
	
	if (cgiFormString("setkey", buf, sizeof(buf)-1) != cgiFormSuccess) {
	    printf("\r\nNO bad setkey parameter\r\n");
	    /* xxx log */
	    exit(1);
	}

	doit(peer, SETKEY, buf);
    } 
    else {
	/* we're just downloading the existing key */
	doit(peer, FETCHKEY, NULL);
    }
    return 0;
}

#endif
