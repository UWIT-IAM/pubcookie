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
#define PBC_DES_INDEX1_FOLDER 30

void main() {
    FILE                *fp;
    unsigned char 	*key_buf;
    int			x = 255;

    key_buf = (unsigned char *)libpbc_alloc_init(PBC_DES_KEY_BUF);

    while( 1 ) 
	printf("index is %d\n", libpbc_get_crypt_index());

    exit(0);
    
    if( ! (fp = pbc_fopen(PBC_CRYPT_KEYFILE, "r")) )
        libpbc_abend("libpbc_crypt_key: Failed open \n");
    
    if( fread(key_buf, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF)
        libpbc_abend("libpbc_crypt_key: Failed read\n");
    fclose(fp);

    key_buf = mod_crypt_key(key_buf);
    
    fp = pbc_fopen("out2", "w");
    if( fwrite(key_buf, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF)
	libpbc_abend("libpbc_crypt_key: Failed write\n");
    fclose(fp);

    exit(0);

}
