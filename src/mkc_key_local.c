#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

void usage(const char *progname) {
    printf("%s -i ip [-o out_file] [-h]\n\n", progname);
    exit (1);
}

int main(int argc, char **argv) {
    unsigned char 	*key_buf;
    unsigned long int   addr;
    unsigned char       *addr_s;
    FILE		*fp;
    FILE		*op;
    char		*out_file = NULL;
    char		*ip = NULL;
    int 		c, barfarg = 0;

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "ho:i:")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	case 'o' :
	    out_file = strdup(optarg);
	    break;
	case 'i' :
	    ip = strdup(optarg);
	    break;
	default :
	    barfarg++;
	    usage(argv[0]);
	}
    }

    if ( ! ip ) {
        printf("\nMust specifiy IP\n");
	usage(argv[0]);
    }

    if ( out_file ) {
        if( ! (op = pbc_fopen(out_file, "w")) )
            libpbc_abend("cannot open the output key file %s for writing\n", out_file);
    } else {
	op = stdout;
    }

    key_buf = (unsigned char *)libpbc_alloc_init(PBC_DES_KEY_BUF);
    addr_s = (unsigned char *)libpbc_alloc_init(sizeof(addr));

    if( ! (fp = pbc_fopen(PBC_CRYPT_KEYFILE, "r")) )
        libpbc_abend("make localized crypt key: Failed open\n");

    if( fread(key_buf, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF)
        libpbc_abend("make localized crypt key: Failed read\n");

    addr = inet_addr(ip);
    memcpy(addr_s, &addr, sizeof(addr));

    key_buf = libpbc_mod_crypt_key(key_buf, addr_s);
    
    if( fwrite(key_buf, sizeof(char), PBC_DES_KEY_BUF, op) != PBC_DES_KEY_BUF)
	libpbc_abend("libpbc_crypt_key: Failed write\n");

    exit(0);

}
