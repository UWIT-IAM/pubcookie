
/* Copyright 1999, University of Washington.  All rights reserved. */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pem.h>
#include <rand.h>
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
