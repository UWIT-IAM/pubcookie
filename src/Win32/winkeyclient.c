/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
  $Id: winkeyclient.c,v 1.4 2003-09-26 22:27:02 ryanc Exp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <winsock.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;


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

#include "../pbc_config.h"
#include "../pbc_configure.h"
#include "../libpubcookie.h"
#include "../strlcpy.h"
#include "../snprintf.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>

#  ifdef __STDC__
extern char * optarg;
#  endif /* __STDC__ */
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#  include "debug.h"
#  include "WebClient.h"
#  include <process.h>
#  include <io.h>
#  define pid_t int
#  define snprintf _snprintf

/* globals */
int noop = 0;
char *SystemRoot;

int Messagef(const char * format, ...){
    char msg[2048];

	va_list   args;

    va_start(args, format);

    _vsnprintf(msg, sizeof(msg)-1, format, args);

	MessageBox(NULL,msg,"Keyclient",MB_OK);

    va_end(args);

    return 1;
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

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile(const char *peername, char *buf)
{
	char SystemRootBuff[MAX_PATH+1];

    strlcpy(buf, PBC_KEY_DIR, 1024);

    if (buf[strlen(buf)-1] != '/') {
        strlcat(buf, "/", 1024);
    }
    strlcat(buf, peername, 1024);
}

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the PB_C_DES_KEY_BUF-sized key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int set_crypt_key(const char *key, const char *peer)
{
    char keyfile[1024];
    FILE *f;

    make_crypt_keyfile(peer, keyfile);
    if (!(f = fopen(keyfile, "wb"))) {
	return PBC_FAIL;
    }
    fwrite(key, sizeof(char), PBC_DES_KEY_BUF, f);
    fclose(f);

    return PBC_OK;
}

/*                                                                           */
int get_crypt_key(crypt_stuff *c_stuff, const char *peer)
{
    FILE             *fp;
    char             *key_in;
    char keyfile[1024];


    make_crypt_keyfile(peer, keyfile);

    key_in = (char *)malloc(PBC_DES_KEY_BUF);

    if( ! (fp = fopen(keyfile, "rb")) ) { /* win32 - must be binary read */
        Messagef("get_crypt_key: Failed open: %s\n", keyfile);
        return PBC_FAIL;
    }
    
    if( fread(key_in, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
        Messagef("get_crypt_key: Failed read: %s\n", keyfile);
	fclose(fp);
	return PBC_FAIL;
    }
    fclose(fp);

    memcpy(c_stuff->key_a, key_in, sizeof(c_stuff->key_a));
    free(key_in);

    return PBC_OK;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    char *cp;
    char buf[2 * PBC_DES_KEY_BUF]; /* plenty of room for base64 encoding */
    unsigned char thekey[PBC_DES_KEY_BUF];
    crypt_stuff c_stuff;
    char *hostname;
	struct hostent *h;
    int newkeyp,ret;
    int done = 0;
    const char *keymgturi = NULL;
    char *keyhost = NULL;
	char *keymgtpath = NULL;
    int keyport = 443;
    pool *p = NULL;
	WSADATA wsaData;
    SOCKET  Socket;
    CtxtHandle hContext;
    SecBuffer  ExtraData;
    SECURITY_STATUS Status;
    SecurityFunctionTable *lpSecurityFunc = NULL;
    PCCERT_CONTEXT pRemoteCertContext = NULL;
	CredHandle hClientCreds;
	char *Reply = NULL;
	char sztmp[1024];
	char *fp[1];
	char SystemRootBuff[MAX_PATH+1];


	strcpy(Instance,"KeyClient");  
		
	if( WSAStartup((WORD)0x0101, &wsaData ) ) 
	{  
		Messagef("Unable to initialize WINSOCK: %d\n", WSAGetLastError() );
		return ERROR_INSTALL_FAILURE;
	}
    if(!LoadSecurityLibrary(&lpSecurityFunc))
    {
        Messagef("Error initializing the security library\n");
        return ERROR_INSTALL_FAILURE;
    }

    libpbc_config_init(p, NULL, "keyclient");

	SystemRoot = malloc(MAX_PATH*sizeof(char));
	if (strlen((fp[0] = PBC_SYSTEM_ROOT)) > 0) {
		strcpy(SystemRoot,fp[0]);
	}
	else {
		GetSystemDirectory(SystemRoot,MAX_PATH);
	}
	free(fp[0]);

	gethostname(sztmp, sizeof(sztmp)-1);
	h = gethostbyname(sztmp);
	hostname = strdup(h->h_name);
    newkeyp = 1;//TODO: make option to just download, newkeyp=0;

    //
    // Create credentials.
    //

	if(Status = CreateCredentials(hostname, &hClientCreds))
	{
		if (Status == SEC_E_NO_CREDENTIALS) {
			Messagef("Error creating credentials.  Could not find server certificate for %s",hostname);
			return ERROR_INSTALL_FAILURE;
		}
		else {
			Messagef("Error creating credentials. Error code: 0x%x\n", Status);
			return ERROR_INSTALL_FAILURE;
		}
	}


    /* figure out the key management server */
	if (!keymgturi) {
		keymgturi = (fp[0] = PBC_KEYMGT_URI);
		free(fp[0]);
	}
    keyhost = strdup(keymgturi);

    if (!strncmp(keyhost, "https://", 8)) keyhost += 8;
    cp = strchr(keyhost, '/');
    if (cp) {
		keymgtpath = strdup(cp);
        *cp = '\0';
    }

    cp = strchr(keyhost, ':');
    if (cp) {
        *cp++ = '\0';
        keyport = atoi(cp);
    }

    /* connect to the keyserver */

    if(ret = ConnectToServer(keyhost, keyport, &Socket))
    {
		Messagef("Cannot connect to %s:%u\n",keyhost,keyport);
        return ERROR_INSTALL_FAILURE;
    }


    //
    // Perform handshake
    //

    if(PerformClientHandshake(Socket,
                              &hClientCreds,
                              keyhost,
                              &hContext,
                              &ExtraData))
    {
        Messagef("Error performing handshake\n");
        return ERROR_INSTALL_FAILURE;
    }


    //
    // Authenticate server's credentials.
    //

    // Get server's certificate.
    Status = lpSecurityFunc->QueryContextAttributes(&hContext,
                                    SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                    (PVOID)&pRemoteCertContext);
    if(Status != SEC_E_OK)
    {
        Messagef("Error 0x%x querying remote certificate\n", Status);
        return ERROR_INSTALL_FAILURE;
    }

    // Display server certificate chain.
    // DisplayCertChain(pRemoteCertContext, FALSE);

    // Attempt to validate server certificate.
    Status = VerifyServerCertificate(pRemoteCertContext,
                                     keyhost,
                                     0);
    if(Status)
    {
        Messagef("Error authenticating server credentials.  Check to make sure that your server has a certificate that is trusted by your machine.\n");

        exit(ERROR_INSTALL_FAILURE);
    }



    /* make the HTTP query */
    if (newkeyp == -1) {
        char enckey[PBC_DES_KEY_BUF * 2];

        if (get_crypt_key(&c_stuff, hostname) != PBC_OK) {
            Messagef("couldn't retrieve key\r\n");
            exit(ERROR_INSTALL_FAILURE);
        }

        libpbc_base64_encode(cp, c_stuff.key_a, (unsigned char *) enckey, PBC_DES_KEY_BUF);

        /* we're uploading! */
        snprintf(buf, sizeof(buf),
                 "%s?genkey=put?setkey=%s;%s",
                 keymgtpath, hostname, enckey);
    } else {
        snprintf(buf, sizeof(buf), 
                 "%s?genkey=%s", keymgtpath,
                 newkeyp ? "yes" : "no");
    }


    if (noop && newkeyp) {
        Messagef("-n specified; not performing any writes:\n");
        Messagef("%s", buf);
        exit(ERROR_INSTALL_FAILURE);
    }
    if(HttpsGetFile(Socket, 
                    &hClientCreds,
                    &hContext, 
                    buf,
					&Reply))
    {
        Messagef("Error fetching file from server.\n");
        return ERROR_INSTALL_FAILURE;
    }

	cp = Reply;
    /* look for the 'OK' */
    while (*cp) {
        if (cp[0] == '\r' && cp[1] == '\n' &&
            cp[2] == 'O' && cp[3] == 'K' &&
            cp[4] == ' ') {
            cp += 5;
            /* cp points to a base64 key we should decode */
            if (strlen(cp) >= (4 * PBC_DES_KEY_BUF + 100) / 3) {
                Messagef("key too long\n");
                exit(ERROR_INSTALL_FAILURE);
            }

            if (newkeyp != -1) {
                if (strchr(cp, '\r')) {
                    /* chomp new line */
                    *(strchr(cp, '\r')) = '\0';
                }
                if (strchr(cp, '\n')) {
                    /* chomp new line */
                    *(strchr(cp, '\n')) = '\0';
                }

                if (noop) {
                    Messagef("would have set key to '%s'\n", cp);
                } else {
		    int osize = 0;
                    int ret;
                    if (strchr(cp, '\r')) {
                        /* chomp new line */
                        *strchr(cp, '\r') = '\0';
                    }
                    ret = libpbc_base64_decode(cp, (unsigned char *) cp, thekey, &osize);
		    if (osize != PBC_DES_KEY_BUF) {
                        Messagef("keyserver returned wrong key size: expected %d got %d\n", PBC_DES_KEY_BUF, osize);
                        exit(ERROR_INSTALL_FAILURE);
                    }

                    if (! ret) {
                        Messagef( "Bad base64 decode.\n" );
                        exit(ERROR_INSTALL_FAILURE);
                    }

                    if (set_crypt_key((const char *) thekey, hostname) != PBC_OK) {
                        Messagef("Cannot store key.  Make sure that key path (%s) exists and can be written to.\n",PBC_KEY_DIR);
                        exit(ERROR_INSTALL_FAILURE);
                    }
                }
            }

            done = 1;
            break;
        }
        cp++;
    }

    //
    // Cleanup.
    //

    if(DisconnectFromServer(Socket, &hClientCreds, &hContext))
    {
        Messagef("Error disconnecting from server\n");
    }


    // Free SSPI credentials handle.
    lpSecurityFunc->FreeCredentialsHandle(&hClientCreds);

    // Close socket.
    closesocket(Socket);

    // Shutdown WinSock subsystem.
    WSACleanup();

    // Close certificate store.
    CertCloseMyStore();

	if (!done) {
		Messagef("Operation failed.\nYou will need to sucessfully run keyclient and obtain a key before using the Pubcookie filter.\n\nServer Reply:\n%s", Reply);
		exit(ERROR_INSTALL_FAILURE);
    }


    return ERROR_SUCCESS;
}
