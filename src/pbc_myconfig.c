/* pbc_myconfig.c -- Configuration routines
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/*
 * $Revision: 1.7 $
 */

/* xxx this should almost certainly use the registry on windows */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "pbc_config.h"
#include "pbc_myconfig.h"

extern int errno;

struct configlist {
    char *key;
    char *value;
};

static struct configlist *configlist;
static int nconfiglist;

static void config_read(const char *alt_config);
static void fatal(const char *s, int ex);

int libpbc_config_init(const char *alt_config, const char *ident)
{
    const char *val;
    int umaskval = 0;
    
    config_read(alt_config);
    
    /* Look up umask */
    val = libpbc_config_getstring("umask", "022");
    while (*val) {
        if (*val >= '0' && *val <= '7') umaskval = umaskval*8 + *val - '0';
        val++;
    }
    umask(umaskval);

    /* paranoia checks */

    /* check that our login host is in our enterprise domain */
    if (!strstr(PBC_LOGIN_HOST, PBC_ENTRPRS_DOMAIN)) {

    }

    /* xxx check that our login URI points to our login host */

    /* xxx check that keydir exists */

    /* xxx check that we can read our symmetric key */

    /* xxx check that the granting certificate (public key) is readable */
    
    return 0;
}

const char *libpbc_config_getstring(const char *key, const char *def)
{
    int opt;

    if ( key == NULL )
        return def;
    
    for (opt = 0; opt < nconfiglist; opt++) {
        if (*key == configlist[opt].key[0] &&
            !strcmp(key, configlist[opt].key))
	    return configlist[opt].value;
    }
    return def;
}

/* output must be free'd.  (no subpointers should be free'd.) */
char **libpbc_config_getlist(const char *key)
{
    const char *tval = libpbc_config_getstring(key, NULL);
    char *val;
    char **ret;
    char *p;
    int c;

    if (tval == NULL) {
	return NULL;
    }

    c = 1; /* initial string */
    for (p = strchr(tval, ' '); p != NULL; p = strchr(p + 1, ' ')) {
	c++;
    }

    /* we malloc a buffer long enough for the subpointers followed by
       the string that we modify by adding \0 */
    ret = malloc(sizeof(char *) * (c + 2) + strlen(tval) + 1);
    if (!ret) {
	fatal("out of memory", EX_OSERR);
    }

    /* copy the string to the end of the buffer.
       assumes sizeof(char) = 1 */
    val = ((char *) ret) + (sizeof(char *) * (c + 2));

    strcpy(val, tval);
    c = 0;
    ret[c++] = val;
    for (p = strchr(val, ' '); p != NULL; p = strchr(p, ' ')) {
	*p++ = '\0';
	if (*p == ' ') continue;
	ret[c++] = p;
    }
    ret[c] = NULL;

    return ret;
}

int libpbc_config_getint(const char *key, int def)
{
    const char *val = libpbc_config_getstring(key, (char *)0);
    
    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
        return def;
    return atoi(val);
}

int libpbc_config_getswitch(const char *key, int def)
{
    const char *val = libpbc_config_getstring(key, (char *)0);

    if (!val) return def;
    
    if (*val == '0' || *val == 'n' ||
        (*val == 'o' && val[1] == 'f') || *val == 'f') {
        return 0;
    }
    else if (*val == '1' || *val == 'y' ||
             (*val == 'o' && val[1] == 'n') || *val == 't') {
        return 1;
    }

    return def;
}

#define CONFIGLISTGROWSIZE 30 /* 100 */
static void config_read(const char *alt_config)
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *p, *q, *key;
    
    infile = fopen(alt_config ? alt_config : PBC_CONFIG, "r");
    if (!infile) {
        snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
                 alt_config ? alt_config : PBC_CONFIG,
                 strerror(errno));
        fatal(buf, EX_CONFIG);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
        lineno++;
	
        if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
        for (p = buf; *p && isspace((int) *p); p++);
        if (!*p || *p == '#') continue;

        key = p;
        while (*p && (isalnum((int) *p) || *p == '-' || *p == '_' || *p == '.')) {
            if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
            p++;
        }
        if (*p != ':') {
            snprintf(buf, sizeof(buf),
		     "invalid option name on line %d of configuration file",
		     lineno);
            fatal(buf, EX_CONFIG);
        }
        *p++ = '\0';
	
        while (*p && isspace((int) *p)) p++;
	
        /* remove trailing whitespace */
        for (q = p + strlen(p) - 1; q > p && isspace((int) *q); q--) {
            *q = '\0';
        }
        
        if (!*p) {
            snprintf(buf, sizeof(buf),
                     "empty option value on line %d of configuration file",
                     lineno);
            fatal(buf, EX_CONFIG);
        }
	
        if (nconfiglist == alloced) {
            alloced += CONFIGLISTGROWSIZE;
            configlist = (struct configlist *)
                realloc((char *)configlist, alloced*sizeof(struct configlist));
            if (!configlist) {
                fatal("out of memory", EX_OSERR);
            }
        }
	
        configlist[nconfiglist].key = strdup(key);
        if (!configlist[nconfiglist].key) {
            fatal("out of memory", EX_OSERR);
        }
        configlist[nconfiglist].value = strdup(p);
        if (!configlist[nconfiglist].value) {
            fatal("out of memory", EX_OSERR);
        }
        nconfiglist++;
    }
    fclose(infile);
}

static void fatal(const char *s, int ex)
{
    fprintf(stderr, "fatal error: %s\n", s);
    exit(ex);
}

#ifdef TEST_MYCONFIG
/* a short test program for pbc_myconfig */

#include <stdio.h>

int errno;

int main(int argc, char *argv[])
{
    char **v;
    int c;

    libpbc_config_init((argc > 1) ? argv[1] : "myconf", NULL);

    v = libpbc_config_getlist("foo");
    if (v) {
        c = 0;
        while (v[c]) {
            printf("'%s'\n", v[c]);
            c++;
        }
        printf("c = %d\n", c);
    } else {
        printf("NULL\n");
        exit(1);
    }

    return 0;
}
#endif
