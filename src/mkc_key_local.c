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

void main() {
    unsigned char 	*key_buf;
    unsigned char       *addr;

    key_buf = (unsigned char *)libpbc_alloc_init(PBC_DES_KEY_BUF);

    if( fread(key_buf, sizeof(char), PBC_DES_KEY_BUF, stdin) != PBC_DES_KEY_BUF)
        libpbc_abend("libpbc_crypt_key: Failed read\n");

    addr = libpbc_gethostip();
    key_buf = libpbc_mod_crypt_key(key_buf, addr);
    
    if( fwrite(key_buf, sizeof(char), PBC_DES_KEY_BUF, stdout) != PBC_DES_KEY_BUF)
	libpbc_abend("libpbc_crypt_key: Failed write\n");

    exit(0);

}
