/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file security.c
 * Support for security structure
 *
 * $Id: security.c,v 1.9 2004-02-16 17:05:31 jteaton Exp $
 */


#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "security.h"

void printme(pool *p, char *desc, char *str, int sz)
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
    security_context *sectext;

    if (argc != 2) {
	fprintf(stderr, "%s <string>\n", argv[0]);
	exit(1);
    }

    libpbc_config_init(p, NULL, "security");

    printf("initializing...\n");
    if (security_init(p, &sectext)) {
	printf("failed\n");
	exit(1);
    }
    printf("ok\n");

    in = argv[1];
    inlen = strlen(in);
    printf("signing '%s'...\n", in);
    if (libpbc_mk_safe(p, sectext, NULL, 0, in, inlen, &outbuf, &outlen)) {
	printf("libpbc_mk_safe() failed\n");
	exit(1);
    }
    printme(p, "sig", outbuf, outlen);

    printf("verifying sig...");
    if (libpbc_rd_safe(p, sectext, NULL, 0, in, inlen, outbuf, outlen)) {
	printf("libpbc_rd_safe() failed\n");
	exit(1);
    }
    printf("ok\n");

    printf("encrypting '%s'...\n", in);
    if (libpbc_mk_priv(p, sectext, NULL, 0, in, inlen, &outbuf, &outlen)) {
	printf("libpbc_mk_priv() failed\n");
	exit(1);
    }
    printme(p, "blob", outbuf, outlen);

    printf("decrypting blob...\n");
    if (libpbc_rd_priv(p, sectext, NULL, 0, outbuf, outlen, &out2buf, &out2len)) {
	printf("libpbc_rd_priv() failed\n");
	exit(1);
    }
    printme(p, "plaintext", out2buf, out2len);
    if (inlen != out2len || strncmp(in, out2buf, inlen)) {
	printf("encryption/decryption FAILED (%s %s)\n", in, out2buf);
	exit(1);
    }
    
}
