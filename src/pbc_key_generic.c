/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_key_generic.c
 * old key management
 *
 * $Id: pbc_key_generic.c,v 1.8 2004-02-10 00:42:15 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/rand.h>
#else
# include <pem.h>
# include <rand.h>
#endif /* OPENSSL_IN_DIR */

#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int main() {
    unsigned char	buf[PBC_DES_KEY_BUF];
    pid_t               pid;

    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    libpbc_augment_rand_state(buf, sizeof(pid));

    RAND_bytes(buf, PBC_DES_KEY_BUF);

    fwrite(buf, sizeof(char), PBC_DES_KEY_BUF, stdout);
    fflush(stdout);

    exit (0);

}
