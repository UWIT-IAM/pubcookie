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

void *main() {
    unsigned char	buf[PBC_4K];
    pid_t               pid;

    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    libpbc_augment_rand_state(buf, sizeof(pid));

    RAND_bytes(buf, PBC_4K);

    fwrite(buf, sizeof(char), PBC_4K, stdout);
    fflush(stdout);

    exit (0);

}
