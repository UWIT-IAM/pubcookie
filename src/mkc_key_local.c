#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pem.h>
#include <unistd.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

int main(int argc, char **argv) {
    unsigned char 	*key_buf;
    unsigned char       *addr;
    FILE		*fp;

    key_buf = (unsigned char *)libpbc_alloc_init(PBC_DES_KEY_BUF);

    if( ! (fp = pbc_fopen(PBC_CRYPT_KEYFILE, "r")) )
        libpbc_abend("make localized crypt key: Failed open\n");

    if( fread(key_buf, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF)
        libpbc_abend("make localized crypt key: Failed read\n");

    addr = argv[1];
    key_buf = libpbc_mod_crypt_key(key_buf, addr);
    
    if( fwrite(key_buf, sizeof(char), PBC_DES_KEY_BUF, stdout) != PBC_DES_KEY_BUF)
	libpbc_abend("libpbc_crypt_key: Failed write\n");

    exit(0);

}
