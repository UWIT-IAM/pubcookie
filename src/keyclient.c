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

    a simple program for downloading DES keys from the login server
    it acts vaguely like an HTTP client

 */

/*
    $Id: keyclient.c,v 2.23 2002-10-23 16:35:25 jjminer Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
#else
# include <pem.h>
# include <crypto.h>
# include <x509.h>
# include <ssl.h>
# include <err.h>
# include <rand.h>
#endif /* OPENSSL_IN_DIR */

#include "pbc_config.h"
#include "pbc_myconfig.h"
#include "libpubcookie.h"
#include "strlcpy.h"

#ifdef WIN32
   char *SystemRoot;
#  include "Win32/debug.h"
#  include "Win32/getopt.h"
#  include <process.h>
#  include <io.h>
#  define pid_t int
#  define snprintf _snprintf
#endif



/* globals */
int noop = 0;

static void usage(void)
{
    printf("usage: keyclient [options]\n");
    printf("  -c <cert file>     : cert to use for TLS authentication\n");
    printf("  -k <key file>      : key to use for TLS authentication\n");
    printf("  -n                 : just show what would be done\n");
    printf("  -d                 : don't generate a new key, just download\n");
    printf("                       the existing one\n");
    printf("  -u                 : upload the local copy of the key\n");
    printf("  -a                 : expect keyfile in ASN.1\n");
    printf("  -p (default)       : expect keyfile in PEM\n");
    printf("  -h <hostname>      : pretend to be <hostname> (dangerous!)\n");
    printf("  -L <hostname>      : connect to loginhost <hostname>\n");
    printf("  -C <cert file>     : CA cert to use for client verification\n");
    printf("  -D <ca dir>        : directory of trusted CAs, hashed OpenSSL-style\n");

    exit(1);
}

/* destructively returns the value of the CN */
static char *extract_cn(char *s)
{
    char *p = strstr(s, "CN=");
    char *q;

    if (p) {
        p += 3;
        q = strstr(p, "/Email=");
        if (q) {
            *q = '\0';
        }
        /* fix for subjects that go leaf -> root */
        q = strchr(p, '/');
        if (q) {
            *q = '\0';
        }
    }

    return p;
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
    const char *hostname;
    int newkeyp;
    X509 *server_cert;
    const char *keyfile;
    const char *certfile;
    const char *cafile = NULL;
    const char *cadir = NULL;
    int done = 0;
    int c;
    int filetype = SSL_FILETYPE_PEM;
    const char *keymgturi = NULL;
    char *keyhost = NULL;
    int keyport = 443;
    int r;

#ifdef WIN32
	SystemRoot = malloc(MAX_PATH*sizeof(char));
	GetEnvironmentVariable ("windir",SystemRoot,MAX_PATH);
	strcat(SystemRoot,"\\System32");
	strcpy(Instance,"KeyClient");
	{   
		
		WSADATA wsaData;
		
		if( WSAStartup((WORD)0x0101, &wsaData ) ) 
		{  
			fprintf(stderr,"Unable to initialize WINSOCK: %d", WSAGetLastError() );
			return -1;
		}
	}   
#endif

    libpbc_config_init(NULL, "keyclient");
    libpbc_pubcookie_init();
    keyfile = libpbc_config_getstring("ssl_key_file", "server.pem");
    certfile = libpbc_config_getstring("ssl_cert_file", "server.pem");
    cafile = libpbc_config_getstring("ssl_ca_file", NULL);
    cadir = libpbc_config_getstring("ssl_ca_path", NULL);

    hostname = NULL;

    newkeyp = 1;
    while ((c = getopt(argc, argv, "apc:k:C:D:nudH:L:")) != -1) {
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

            case 'H':
                hostname = strdup(optarg);
                break;

            case 'L':
                /* connect to the specified login server */
                keyhost = strdup(optarg);
                break;

            case '?':
            default:
                usage();
                break;
        }
    }

    /* initalize the PRNG as best we can if we have to */
    if (RAND_status() == 0) {
        time_t t = time(NULL);
        pid_t pid = getpid();
#ifndef WIN32
        char buf[1024];
#endif
        char *cmd[3] = {"/bin/ps", "-ef", NULL};

        RAND_seed((unsigned char *)&t, sizeof(t));
        RAND_seed((unsigned char *)&pid, sizeof(pid));

#ifndef WIN32
        capture_cmd_output(cmd, buf, sizeof(buf));
        RAND_seed((unsigned char *)buf, sizeof(buf));
#endif
    }

    /* Load SSL Error Strings */
    SSL_load_error_strings();

    /* initialize the OpenSSL connection */
    SSL_library_init();

    ctx = SSL_CTX_new(TLSv1_client_method());

    /* setup the correct certificate */
    if (!SSL_CTX_use_certificate_file(ctx, certfile, filetype)) {
        fprintf(stderr, "SSL_CTX_use_certificate_file:\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(ctx, keyfile, filetype)) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file:\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_load_verify_locations(ctx, cafile, cadir)) {
        fprintf(stderr, "SSL_CTX_load_verify_locations failed:\n");
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "(set 'ssl_ca_file' or 'ssl_ca_path'?)\n");
        exit(1);
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_connect() failed:\n");
        ERR_print_errors_fp(stderr);
    }

    /* figure out the key management server */
    keymgturi = libpbc_config_getstring("keymgt_uri", NULL);
    if (keymgturi ==  NULL) {
        keymgturi = malloc(1024);
        snprintf((char *) keymgturi, 1024, "https://%s/cgi-bin/keyserver", 
                 PBC_LOGIN_HOST);
    }

    if (!keyhost) {
        keyhost = strdup(keymgturi);
    }

    if (!strncmp(keyhost, "https://", 8)) keyhost += 8;
    p = strchr(keyhost, '/');
    if (p) {
        *p = '\0';
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
#ifdef WIN32
    sa.sin_port = htons((unsigned short)keyport);
#else
    sa.sin_port = htons(keyport);
#endif

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
    p = extract_cn(str);
    if (p == NULL) {
        fprintf(stderr, "str == NULL???\n");
        exit(1);
    }
    if (strcasecmp(p, PBC_LOGIN_HOST)) {
        fprintf(stderr, "certificate presented isn't the login host: %s != %s\n",
                p, PBC_LOGIN_HOST);
        exit(1);
    }
    free(str);

    if (!hostname) {
        X509 *mycert;
        /* retrieve the hostname from the client cert we're using */
        mycert = SSL_get_certificate(ssl);
        if (mycert == NULL) {
            fprintf(stderr, "mycert == NULL???\n");
            exit(1);
        }

        str = X509_NAME_oneline (X509_get_subject_name (mycert),0,0);
        hostname = extract_cn(str);
        if (hostname) {
            /* warn if hostname != get_my_hostname() */
            if (strcasecmp(hostname, get_my_hostname())) {
                fprintf(stderr, "warning: certificate name (%s) doesn't match"
                        " my hostname (%s)\n", hostname, get_my_hostname());
            }
        } else {
            fprintf(stderr, 
                    "warning: no hostname in my certificate? trying anyway.\n");
            hostname = get_my_hostname();
        }
    }

    /* make the HTTP query */
    if (newkeyp == -1) {
        char enckey[PBC_DES_KEY_BUF * 2];

        if (libpbc_get_crypt_key(&c_stuff, hostname) != PBC_OK) {
            fprintf(stderr, "couldn't retrieve key\r\n");
            exit(1);
        }

        libpbc_base64_encode(c_stuff.key_a, (unsigned char *) enckey, PBC_DES_KEY_BUF);

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
        fprintf(stderr, "SSL_write failed:\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    p = buf;
    for (;;) {
        /* read the response */
        r = SSL_read(ssl, p, sizeof(buf) - 1 - (p - buf));
        if (r < 0) {
            fprintf(stderr, "SSL_read failed:\n");
            ERR_print_errors_fp(stderr);
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
                if (strchr(p, '\r')) {
                    /* chomp new line */
                    *(strchr(p, '\r')) = '\0';
                }
                if (strchr(p, '\n')) {
                    /* chomp new line */
                    *(strchr(p, '\n')) = '\0';
                }

                if (noop) {
                    printf("would have set key to '%s'\n", p);
                } else {
		    int osize = 0;
                    int ret;
                    if (strchr(p, '\r')) {
                        /* chomp new line */
                        *strchr(p, '\r') = '\0';
                    }
                    ret = libpbc_base64_decode( (unsigned char *) p, thekey, &osize);
		    if (osize != PBC_DES_KEY_BUF) {
                        fprintf(stderr, "keyserver returned wrong key size: expected %d got %d\n", PBC_DES_KEY_BUF, osize);
                        exit(1);
                    }

                    if (! ret) {
                        fprintf( stderr, "Bad base64 decode.\n" );
                        exit(1);
                    }

                    if (libpbc_set_crypt_key( (const char *) thekey, hostname) != PBC_OK) {
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
