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

    a simple program for downloading DES keys from the login server
    it acts vaguely like an HTTP client
 */

/*
    $Id: keyclient.c,v 2.1 2002-06-05 16:52:29 greenfld Exp $
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "pbc_config.h"
#include "pbc_myconfig.h"
#include "libpubcookie.h"

/* globals */
int noop = 0;

static void usage(void)
{
    printf("usage: keyclient [options]\n");
    printf("  -c <key/cert file> : key to use for TLS authentication\n");
    printf("  -n                 : just show what would be done\n");
    printf("  -d                 : don't generate a new key, just download\n");
    printf("                       the existing one\n");
    printf("  -u                 : upload the local copy of the key\n");
    printf("  -a                 : expect keyfile in ASN.1\n");
    printf("  -p (default)       : expect keyfile in PEM\n");
    printf("  -h <hostname>      : pretend to be <hostname> (dangerous!)\n");
    printf("  -L <hostname>      : connect to loginhost <hostname>\n");

    exit(1);
}


int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sd;
    struct sockaddr_in sa;
    struct hostent *h;
    char *str, *p;
    char buf[2 * PBC_DES_KEY_BUF]; /* plenty of room for base64 encoding */
    unsigned char thekey[PBC_DES_KEY_BUF];
    crypt_stuff c_stuff;
    char hostname[1024];
    int newkeyp;
    SSL_METHOD *meth;
    X509 *server_cert;
    const char *keyfile = "server.pem";
    int done = 0;
    int c;
    int filetype = SSL_FILETYPE_PEM;
    const char *keymgturi = NULL;
    char *keyhost = NULL;
    int keyport = 443;
    int r;

    libpbc_config_init(NULL, "keyclient");

    if (gethostname(hostname, sizeof(hostname)) < 0) {
	perror("gethostname");
	exit(1);
    }

    newkeyp = 1;
    while ((c = getopt(argc, argv, "apc:nudh:")) != -1) {
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

	case 'n':
	    /* noop */
	    noop = 1;
	    break;

	case 'd':
	    /* download, don't generate a new key */
	    newkeyp = 0;
	    break;

	case 'u':
	    /* upload, don't generate a new key */
	    newkeyp = -1;
	    break;

	case 'L':
	    /* connect to the specified login server */
	    keyhost = strdup(optarg);
	    break;

	case 'h':
	    strlcpy(hostname, optarg, sizeof hostname);
	    break;
	    
	case '?':
	default:
	    usage();
	    break;
	}
    }

    /* initialize the OpenSSL connection */
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLSv1_client_method());

    /* setup the correct certificate */
    SSL_CTX_use_certificate_file(ctx, keyfile, filetype);
    SSL_CTX_use_PrivateKey_file(ctx, keyfile, filetype);

    ssl = SSL_new(ctx);

    /* figure out the key management server */
    keymgturi = libpbc_config_getstring("keymgt_uri", NULL);
    if (keymgturi ==  NULL) {
	keymgturi = malloc(1024);
	snprintf((char *) keymgturi, 1024, "https://%s/cgi-bin/keyserver", 
		 PBC_LOGIN_HOST);
    }

    if (!keyhost) {
	keyhost = strdup(keymgturi);
	if (!strncmp(keyhost, "https://", 8)) keyhost += 8;
	p = strchr(keyhost, '/');
	if (p) {
	    *p = '\0';
	}
    }

    p = strchr(keyhost, ':');
    if (p) {
	*p++ = '\0';
	keyport = atoi(p);
    }

    /* connect to the keyserver */
    sd = socket (AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
	perror("socket");
	exit(1);
    }

    sa.sin_family = AF_INET;
    h = gethostbyname(keyhost);
    if (!h) {
	perror("gethostbyname");
	exit(1);
    }
    memcpy(&sa.sin_addr, h->h_addr, h->h_length);
    sa.sin_port = htons(keyport);

    if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
	perror("connect");
	exit(1);
    }

    /* negotiate SSL */
    SSL_set_fd(ssl, sd);
    if (SSL_connect(ssl) < 0) {
	ERR_print_errors_fp(stderr);
	exit(1);
    }

    /* check certificate */
    server_cert = SSL_get_peer_certificate (ssl);
    if (server_cert == NULL) {
	fprintf(stderr, "server_cert == NULL???\n");
	exit(1);
    }

    str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
    if (str == NULL) {
	fprintf(stderr, "str == NULL???\n");
	exit(1);
    }
    if (!strcasecmp(str, PBC_LOGIN_HOST)) {
	fprintf(stderr, "certificate presented isn't the login host: %s != %s\n",
		str, PBC_LOGIN_HOST);
	exit(1);
    }
    free(str);

    /* make the HTTP query */
    if (newkeyp == -1) {
	char enckey[PBC_DES_KEY_BUF * 2];

	if (libpbc_get_crypt_key(&c_stuff, hostname) != PBC_OK) {
	    fprintf(stderr, "couldn't retrieve key\r\n");
	    exit(1);
	}

	libpbc_base64_encode(c_stuff.key_a, enckey, PBC_DES_KEY_BUF);

	/* we're uploading! */
	snprintf(buf, sizeof(buf),
		 "GET %s?genkey=put?setkey=%s;%s\r\n\r\n",
		 keymgturi, hostname, enckey);
    } else {
	snprintf(buf, sizeof(buf), 
		 "GET %s?genkey=%s HTTP/1.0\r\n\r\n", keymgturi,
		 newkeyp ? "yes" : "no");
    }

    if (noop && newkeyp) {
	printf("-n specified; not performing any writes:\n");
	printf("%s", buf);
	exit(1);
    }

    if (SSL_write(ssl, buf, strlen(buf)) < 0) {
	fprintf(stderr, "SSL_write failed\n");
	exit(1);
    }

    p = buf;
    for (;;) {
	/* read the response */
	r = SSL_read(ssl, p, sizeof(buf) - 1 - (p - buf));
	if (r < 0) {
	    fprintf(stderr, "SSL_read failed\n");
	    exit(1);
	}
	if (r == 0) {
	    break;
	}
	p += r;
	*p = '\0';
    }

    p = buf;
    /* look for the 'OK' */
    while (*p) {
	if (p[0] == '\r' && p[1] == '\n' &&
	    p[2] == 'O' && p[3] == 'K' &&
	    p[4] == ' ') {
	    p += 5;
		
	    /* p points to a base64 key we should decode */
	    if (strlen(p) >= (4 * PBC_DES_KEY_BUF + 100) / 3) {
		fprintf(stderr, "key too long\n");
		exit(1);
	    }

	    if (newkeyp != -1) {
		if (noop) {
		    if (strchr(p, '\r')) {
			/* chomp new line */
			*strchr(p, '\r') = '\0';
		    }
		    printf("would have set key to '%s'\n", p);
		} else {
		    libpbc_base64_decode(p, thekey);
		    if (libpbc_set_crypt_key(thekey, hostname) != PBC_OK) {
			fprintf(stderr, "libpbc_set_crypt_key() failed\n");
			exit(1);
		    }
		}
	    }
		
	    done = 1;
	    goto jump;
	}
	p++;
    }

 jump:
    SSL_shutdown(ssl);

    if (!done) {
	printf("operation failed: %s\n", buf);
    }

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
