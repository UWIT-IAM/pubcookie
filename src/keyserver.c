/*

    Copyright 1999-2002, University of Washington.  All rights reserved.
    see doc/LICENSE.txt for copyright information

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|

    All comments and suggestions to pubcookie@cac.washington.edu
    More information: http://www.pubcookie.org/
    Written by the Pubcookie Team

    a simple program for maintaining keys on the login server 
    
    by default, it should be invoked from inetd and acts vaguely like
    an HTTP server

 */

/*
    $Id: keyserver.c,v 2.24 2002-09-27 17:44:38 greenfld Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif /* HAVE_SYS_WAIT_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
#else
# include <pem.h>
# include <crypto.h>
# include <x509.h>
# include <pem.h>
# include <ssl.h>
# include <err.h>
#endif /* OPENSSL_IN_DIR */

#ifndef KEYSERVER_CGIC
# ifdef HAVE_GETOPT_H
#  include <getopt.h>
# endif /* HAVE_GETOPT_H */
#else /* ifndef KEYSERVER_CGIC */
# ifdef HAVE_CGIC_H
#  include <cgic.h>
# endif /* HAVE_CGIC_H */
#endif /* ifndef KEYSERVER_CGIC */

#include "pbc_config.h"
#include "pbc_logging.h"
#include "libpubcookie.h"

int debug = 0;

#ifndef KEYSERVER_CGIC
static SSL *ssl = NULL;

/**
 * log all outstanding errors from OpenSSL, attributing them to 'func'
 * @param func the function to attribute errors to
 */
static void logerrstr(const char *func)
{
    unsigned long r;

    while ((r = ERR_get_error())) {
	pbc_log_activity(PBC_LOG_ERROR, "%s: %s", 
                         func, ERR_error_string(r, NULL));
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

    if (debug) {
        pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, "Sending: \"%s\"", buf );
    }

    if (SSL_write(ssl, buf, strlen(buf)) < 0) {
	logerrstr("SSL_write");
	exit(1);
    }
}
#else /* ifndef KEYSERVER_CGIC */
void myprintf(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#endif /* ifndef KEYSERVER_CGIC */


const char *keyfile = "server.pem";
const char *certfile = "server.pem";
const char *cadir = NULL;
const char *cafile = NULL;

enum optype {
    NOOP,
    GENKEY,
    SETKEY,
    FETCHKEY
};

/**
 * iterate through the 'login_servers' configuration variable, contacting
 * each one and setting my copy of peer's key on it
 * @param name of the client key to push
 * @return the number of login servers we failed to set the key on
 * (thus 0 is success)
 */
int pushkey(const char *peer)
{
    char **lservers = libpbc_config_getlist("login_servers");
    const char *hostname;
    char *lservername, *p;
    int x;
    int res;
    int fail = 0;

    if (!lservers) {
        /* only me here */
        return(0);
    }

    hostname = get_my_hostname();
    if (!hostname) {
        pbc_log_activity(PBC_LOG_ERROR, "get_my_hostname() failed? %m");
        perror("get_my_hostname");
        exit(1);
    }

    x = 0;
    for (x = 0; lservers[x] != NULL; x++) {
        /* login_servers (should?  might?) contain a URI */

        /* break out the hostname and see if that is us */
        lservername = strdup(lservers[x]);
        if (!strncmp(lservername, "https://", 8)) lservername += 8;
        p = strchr(lservername, '/');
        if (p) {
            *p = '\0';
        }
        p = strchr(lservername, ':');
        if (p) {
            *p = '\0';
        }

        if (!strcasecmp(hostname, lservername)) {
            /* don't push the key to myself */
            free(lservername);
            continue;
        }

        free(lservername);

        pbc_log_activity(PBC_LOG_AUDIT, 
                         "setting %s's key on %s", peer, lservers[x]);

        res = fork();
        if (res < 0) {
            pbc_log_activity(PBC_LOG_ERROR, "fork(): %m");
            perror("fork");
            exit(1);
        }
        if (res == 0) {
            const char *keyclient = (PBC_PATH "bin/keyclient");
            const char *cmd[15] = {
               keyclient,
               "-u",
               "-H", peer,
               "-L", lservers[x],
               "-k", keyfile, 
               "-c", certfile
            };
            int n = 10;
            if (cafile != NULL) {
               cmd[n++] = "-C";
               cmd[n++] = cafile;
            }
            if (cadir != NULL) {
               cmd[n++] = "-D";
               cmd[n++] = cadir;
            }
            cmd[n] = NULL;

            res = execv(keyclient, (char **const) cmd);
            pbc_log_activity(PBC_LOG_ERROR, "execl(): %m");
            for (n=0; cmd[n]!=NULL; n++){
                pbc_log_activity(PBC_LOG_ERROR, "%d %s", n, cmd[n]);
            }
            exit(2);
        }

        /* parent */
        wait(&res);
        pbc_log_activity(PBC_LOG_AUDIT, 
                         "setting %s's key on %s: %s", peer, lservers[x], 
                         WEXITSTATUS(res) == 0 ? "done" : "error");
        if (WEXITSTATUS(res) != 0) {
            fail++;
        }
    }

    free(lservers);

    return fail;
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

                pbc_log_activity(PBC_LOG_AUDIT, "generating a new key for %s",
                                 peer);

                if (libpbc_generate_crypt_key(peer) < 0) {
                    myprintf("NO generate_new_key() failed\r\n");
                    pbc_log_activity(PBC_LOG_ERROR, 
                                     "generate_new_key() failed");

                    return(1);
                }

                /* push the new key to the other login servers */
                pushkey(peer);

                break;
            }

        case SETKEY:
            {
                char *thekey64, *thepeer;
                char *thekey;
                int ksize;

                /* someone has asked us to set a key */

                /* verify that 'peer' is a fellow login server */
                if (strcasecmp(peer, PBC_LOGIN_HOST)) {
                    pbc_log_activity(PBC_LOG_ERROR,
                                     "%s attempted to set a key!", peer);
                    myprintf("NO you are not authorized to set keys\r\n");
                    return (1);
                }

                /* find <peer>;<key> */
                thepeer = strdup(newkey);
                thekey64 = strchr(thepeer, ';');
                if (!thekey64) {
                    myprintf("NO bad form for new key\r\n");
                    /* xxx log */
                    return(1);
                }
                *thekey64++ = '\0';

                /* base64 decode thekey64 */
                thekey = (char *) malloc(strlen(thekey64));
                if (strchr(thekey64, '\r')) {
                        /* chomp new line */
                        *strchr(thekey64, '\r') = '\0';
                }
                if (!thekey || 
                    !libpbc_base64_decode( (unsigned char *) thekey64,
                                   (unsigned char *) thekey, &ksize) || 
                    ksize != PBC_DES_KEY_BUF) {
                    myprintf("NO couldn't decode key\r\n");
                    /* xxx log */
                    return (1);
                }

                /* go ahead and write it to disk */
                if (libpbc_set_crypt_key(thekey, thepeer) != PBC_OK) {
                    myprintf("NO couldn't set key\r\n");
                    /* xxx log */
                    return(1);
                }

                free(thekey);

                pbc_log_activity(PBC_LOG_AUDIT, 
                                 "%s set key for %s!", peer, thepeer);
                myprintf("OK key set\r\n");
                break;
            }

        case FETCHKEY:

            pbc_log_activity(PBC_LOG_AUDIT, "Fetching a key..");

            /* noop; we always return the new key */
            assert(newkey == NULL);
            break;

        case NOOP:

            pbc_log_activity(PBC_LOG_AUDIT, "Noop..");
           /* noop;  just for completeness */
           break;
    }

    /* return the key */
    if (libpbc_get_crypt_key(&c_stuff, (char *) peer) != PBC_OK) {
        myprintf("NO couldn't retrieve key\r\n");
        return 1;
    }

    /* now give the key back to the application */
    libpbc_base64_encode(c_stuff.key_a, (unsigned char *) buf, PBC_DES_KEY_BUF);

    myprintf("OK %s\r\n", buf);
    fflush(stdout);

    return 0;
}

#ifndef KEYSERVER_CGIC

void usage(void)
{
    printf("usage: keyserver [options]\n");
    printf("  -c <cert file>     : certificate to use for TLS authentication\n");
    printf("  -k <key>           : key to use for TLS authentication\n");
    printf("  -a                 : expect keyfile in ASN.1\n");
    printf("  -p (default)       : expect keyfile in PEM\n");
    printf("  -C <cert file>     : CA cert to use for client verification\n");
    printf("  -D <ca dir>        : directory of trusted CAs, hashed OpenSSL-style\n");
    printf("\n");
    printf("All options override the values in the configuration file.\n");
}

static int verify_callback(int ok, X509_STORE_CTX * ctx)
{
    X509   *err_cert;
    int     err;

    pbc_log_activity(PBC_LOG_DEBUG_VERBOSE, 
                     "verifying peer certificate... ok=%d", ok);

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);

    if (!ok) {
	pbc_log_activity(PBC_LOG_ERROR, "verify error:num=%d:%s", err,
                         X509_verify_cert_error_string(err));

	/* we want to ignore any key usage problems but no other faults */
	switch (ctx->error) {
	case X509_V_ERR_INVALID_PURPOSE:
	    pbc_log_activity(PBC_LOG_ERROR, "invalid purpose; ignoring error!");
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
    char *peer = NULL;
    char *p;
    char buf[4096];
    enum optype op = NOOP;
    char *setkey = NULL;
    SSL_CTX *ctx;
    X509 *client_cert;
    int r;

    libpbc_config_init(NULL, "keyserver");
    libpbc_pubcookie_init();

    debug = libpbc_config_getint("debug", 0);
    keyfile = libpbc_config_getstring("ssl_key_file", "server.pem");
    certfile = libpbc_config_getstring("ssl_cert_file", "server.pem");
    cafile = libpbc_config_getstring("ssl_ca_file", NULL);
    cadir = libpbc_config_getstring("ssl_ca_path", NULL);

    while ((c = getopt(argc, argv, "apc:k:C:D:")) != -1) {
	switch (c) {
	case 'a':
	    filetype = SSL_FILETYPE_ASN1;
	    break;

	case 'p':
	    filetype = SSL_FILETYPE_PEM;
	    break;

	case 'c':
	    /* 'optarg' is the certificate file */
	    certfile = strdup(optarg);
	    break;

	case 'k':
	    /* 'optarg' is the key file */
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

    /* initalize the PRNG as best we can if we have to */
    if (RAND_status() == 0) {
        time_t t = time(NULL);
        pid_t pid = getpid();
        char buf[1024];
        char *cmd[3] = {"/bin/ps", "-ef", NULL};

        RAND_seed((unsigned char *)&t, sizeof(t));
        RAND_seed((unsigned char *)&pid, sizeof(pid));

        capture_cmd_output(cmd, buf, sizeof(buf));
        RAND_seed((unsigned char *)buf, sizeof(buf));
    }

    /* Load SSL Error Strings */
    SSL_load_error_strings();

    /* initialize the OpenSSL connection */
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLSv1_server_method());

    /* setup the correct certificate */
    if (!SSL_CTX_use_certificate_file(ctx, certfile, filetype)) {
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
	pbc_log_activity(PBC_LOG_ERROR, "client_cert == NULL???");
	exit(1);
    }

    peer = X509_NAME_oneline (X509_get_subject_name (client_cert),0,0);
    if (peer == NULL) {
	pbc_log_activity(PBC_LOG_ERROR, "peer == NULL???");
	exit(1);
    }
    if (strstr(peer, "CN=")) {
	peer = strstr(peer, "CN=");
	peer += 3;
    }
    if( strstr(peer, "/Email=") ) {
        *(strstr(peer, "/Email=")) = '\0';
    }
    pbc_log_activity(PBC_LOG_AUDIT, "peer identified as %s\n", peer);

    /* read HTTP query */
    if (SSL_read(ssl, buf, sizeof(buf)) <= 0) {
	pbc_log_activity(PBC_LOG_ERROR, "SSL_read() failed");
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
	else if (*p == '?' && !strncmp(p+1, "setkey=", 7)) {
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
	pbc_log_activity(PBC_LOG_ERROR, "peer didn't specify an operation");
	exit(1);
    }

    /* call doit */

    r = doit(peer, op, setkey);
    SSL_shutdown(ssl);

    return r;
}

#else /* ifndef KEYSERVER_CGIC */
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
    debug = libpbc_config_getint("debug", 0);

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

#endif /* ifndef KEYSERVER_CGIC */
