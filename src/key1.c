#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pem.h>
#include <rand.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#define LEN 5

void *main() {
    unsigned char	buf[4096];
    FILE		*fp;
    pid_t               pid;

    pid = getpid();
    memcpy(buf, &pid, sizeof(pid_t));
    libpbc_augment_rand_state(buf, sizeof(pid));

    RAND_bytes(buf, 4096);

    fp = fopen("key1.out", "w");
    fwrite(buf, sizeof(char), 4096, fp);
    fclose(fp);

    exit (0);

}
