#include <stdio.h>

#include "security.h"

void printme(char *desc, char *str, int sz)
{
    int s;

    printf("got %s, size %d:\n", desc, sz);
    for (s = 0; s < sz; s++) {
	if (isprint(str[s])) putchar(str[s]);
	else putchar('.');
    }
    putchar('\n');
}

int main(int argc, char *argv[])
{
    int outlen, out2len;
    char *outbuf, *out2buf;
    char *in;
    int inlen;

    if (argc != 2) {
	fprintf(stderr, "%s <string>\n", argv[0]);
	exit(1);
    }

    libpbc_config_init(NULL, "security");

    printf("initializing...\n");
    if (security_init()) {
	printf("failed\n");
	exit(1);
    }
    printf("ok\n");

    in = argv[1];
    inlen = strlen(in);
    printf("signing '%s'...\n", in);
    if (libpbc_mk_safe(NULL, in, inlen, &outbuf, &outlen)) {
	printf("libpbc_mk_safe() failed\n");
	exit(1);
    }
    printme("sig", outbuf, outlen);

    printf("verifying sig...");
    if (libpbc_rd_safe(NULL, in, inlen, outbuf, outlen)) {
	printf("libpbc_rd_safe() failed\n");
	exit(1);
    }
    printf("ok\n");

    printf("encrypting '%s'...\n", in);
    if (libpbc_mk_priv(NULL, in, inlen, &outbuf, &outlen)) {
	printf("libpbc_mk_priv() failed\n");
	exit(1);
    }
    printme("blob", outbuf, outlen);

    printf("decrypting blob...\n");
    if (libpbc_rd_priv(NULL, outbuf, outlen, &out2buf, &out2len)) {
	printf("libpbc_rd_priv() failed\n");
	exit(1);
    }
    printme("plaintext", out2buf, out2len);
    if (inlen != out2len || strncmp(in, out2buf, inlen)) {
	printf("encryption/decryption FAILED (%s %s)\n", in, out2buf);
	exit(1);
    }
    
}
