/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file pbc_myconfig.c
 * Runtime configuration 
 *
 * $Id: pbc_myconfig.c,v 1.35 2003-09-26 22:27:02 ryanc Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#if defined (APACHE1_3)
# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"
#else
typedef void pool;
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#ifdef HAVE_SYSEXITS_H
# include <sysexits.h>
#else
# define EX_OSERR 71
#endif /* HAVE_SYSEXITS_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

#include "pbc_config.h"
#include "pbc_myconfig.h"
#include "snprintf.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_configure.h"
#include "pbc_logging.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

struct configlist {
    char *key;
    char *value;
};

#define REQUIRED 1
#define NOT_REQUIRED 0

static struct configlist *configlist;
static int nconfiglist;

static void myconfig_read(pool *p, const char *alt_config, int required);
static void fatal(pool *p, const char *s, int ex);

#ifdef WIN32
# include "Win32/debug.h"
#endif

#ifndef WIN32

int libpbc_myconfig_init(pool *p, const char *alt_config, const char *ident)
{
    const char *val;
    int umaskval = 0;
    char *sub_config, *ptr, *ptr2;
    int len;
    
    myconfig_read(p, alt_config, REQUIRED);
    
    /* get the sub config file for the pubcookie sub-system */
    if (ident != NULL ) {
        /* +1 for oes and +1 for extra '/' */
        len = strlen(PBC_PATH) + strlen(ident) + strlen(PBC_SUBCONFIG) + 1 + 1;
        sub_config = pbc_malloc(p, sizeof(char *) * len);
        bzero(sub_config, len);
        snprintf(sub_config, len, "%s/%s%s", PBC_PATH, ident, PBC_SUBCONFIG);
        
        /* remove that extra slash */
        ptr = ptr2 = sub_config;
        while( *ptr2 ) {
            if( ptr2 != sub_config && *ptr2 == '/' &&  *(ptr2-1) == '/' )
                ptr2++;
             else
                *ptr++ = *ptr2++;
        }
        *ptr = '\0';

        myconfig_read(p, sub_config, NOT_REQUIRED);
        free(sub_config);
    }

    /* Look up umask */
    val = libpbc_myconfig_getstring(p, "umask", "022");
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

const char *libpbc_myconfig_getstring(pool *p, const char *key, const char *def)
{
    int opt;

    if ( key == NULL )
        return def;

    for (opt = 0; opt < nconfiglist; opt++) {
        if (configlist[opt].key == NULL ) {
            libpbc_abend( p, "Option key suddenly became NULL!  Somebody fudged a pointer!" );
        }
        if ( *key == configlist[opt].key[0] &&
            !strcmp(key, configlist[opt].key))
	    return configlist[opt].value;
    }
    return def;
}

/* output must be free'd.  (no subpointers should be free'd.) */
char **libpbc_myconfig_getlist(pool *p, const char *key)
{
    const char *tval = libpbc_myconfig_getstring(p, key, NULL);
    char *val;
    char **ret;
    char *ptr;
    int c;

    if (tval == NULL) {
	return NULL;
    }

    c = 1; /* initial string */
    for (ptr = strchr(tval, ' '); ptr != NULL; ptr = strchr(ptr + 1, ' ')) {
	c++;
    }

    /* we malloc a buffer long enough for the subpointers followed by
       the string that we modify by adding \0 */
    ret = pbc_malloc(p, sizeof(char *) * (c + 2) + strlen(tval) + 1);
    if (!ret) {
	fatal(p, "out of memory", EX_OSERR);
    }

    /* copy the string to the end of the buffer.
       assumes sizeof(char) = 1 */
    val = ((char *) ret) + (sizeof(char *) * (c + 2));

    strcpy(val, tval);
    c = 0;
    ret[c++] = val;
    for (ptr = strchr(val, ' '); ptr != NULL; ptr = strchr(ptr, ' ')) {
	*ptr++ = '\0';
	if (*ptr == ' ') continue;
	ret[c++] = ptr;
    }
    ret[c] = NULL;

    return ret;
}

int libpbc_myconfig_getint(pool *p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring(p, key, (char *)0);
    
    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
        return def;
    return atoi(val);
}

int libpbc_myconfig_getswitch(pool *p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring(p, key, (char *)0);

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
static void myconfig_read(pool *p, const char *alt_config, int required)
{
    FILE *infile;
    const char *filename;
    int lineno = 0;
    int alloced = 0;
    char buf[8192];
    char *ptr, *q, *key;
    
    filename = alt_config ? alt_config : PBC_CONFIG;
    infile = pbc_fopen(p, filename, "r");
    if (!infile) {
        if ( required == NOT_REQUIRED ) {
            return;
        }
        snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
                 filename,
                 strerror(errno));
        fatal(p, buf, EX_CONFIG);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
        lineno++;
	
        if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
        for (ptr = buf; *ptr && isspace((int) *ptr); ptr++);
        if (!*ptr || *ptr == '#') continue;

        key = ptr;
        while (*ptr && (isalnum((int) *ptr) || *ptr == '-' || *ptr == '_' || *ptr == '.')) {
            if (isupper((unsigned char) *ptr)) *ptr = tolower((unsigned char) *ptr);
            ptr++;
        }
        if (*ptr != ':') {
            snprintf(buf, sizeof(buf),
		     "invalid option name on line %d of configuration file %s",
		     lineno, filename);
            fatal(p, buf, EX_CONFIG);
        }
        *ptr++ = '\0';
	
        while (*ptr && isspace((int) *ptr)) ptr++;
	
        /* remove trailing whitespace */
        for (q = ptr + strlen(ptr) - 1; q > ptr && isspace((int) *q); q--) {
            *q = '\0';
        }
        
        if (!*ptr) {
            snprintf(buf, sizeof(buf),
                     "empty option value on line %d of configuration file %s",
                     lineno, filename);
            fatal(p, buf, EX_CONFIG);
        }
	
        if (nconfiglist == alloced) {
            alloced += CONFIGLISTGROWSIZE;

            if (configlist == NULL) {
                configlist = (struct configlist *)
                    pbc_malloc(p, alloced*sizeof(struct configlist));
            } else {
                configlist = (struct configlist *)
                    realloc((char *)configlist, alloced*sizeof(struct configlist));
            }
            if (!configlist) {
                fatal(p, "out of memory", EX_OSERR);
            }
        }
	
        configlist[nconfiglist].key = pbc_strdup(p, key);
        if (!configlist[nconfiglist].key) {
            fatal(p, "out of memory", EX_OSERR);
        }
        configlist[nconfiglist].value = pbc_strdup(p, ptr);
        if (!configlist[nconfiglist].value) {
            fatal(p, "out of memory", EX_OSERR);
        }
        nconfiglist++;
    }
    pbc_fclose(p, infile);
}

static void fatal(pool *p, const char *s, int ex)
{
    fprintf(stderr, "fatal error: %s\n", s);
    exit(ex);
}

#ifdef TEST_MYCONFIG
/* a short test program for pbc_myconfig */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */


int errno;

int main(int argc, char *argv[])
{
    char **v;
    int c;

    libpbc_myconfig_init((argc > 1) ? argv[1] : "myconf", NULL);

    v = libpbc_myconfig_getlist("foo");
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

#else  /*WIN32*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <pem.h>
#include <httpfilt.h>
#include "Win32/debug.h"


#define CONFIGLISTGROWSIZE 50

static void fatal(pool *p, const char *s, int ex)
{
	syslog(LOG_ERR, "fatal error: %s\n", s);
    exit(ex);
}


char *libpbc_myconfig_copystring(char **outputstring, const char *inputstring, int size)
{
	if (inputstring != NULL) {
		strncpy(*outputstring,inputstring,MAX_REG_BUFF);  
	}
	else {
		free(*outputstring);
		*outputstring = NULL;
	}
	return *outputstring;
}

char *libpbc_myconfig_getstring(pool *p, char *strbuff, const char *key, const char *def)
{
	char keyBuff[1024];
	HKEY hKey;
	int dsize;

	dsize = MAX_REG_BUFF;
	strcpy (keyBuff,PBC_PUBKEY);  /* config. settings in main pubcookie service key */
	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		keyBuff,0,KEY_READ,&hKey) != ERROR_SUCCESS) {
		libpbc_myconfig_copystring(&strbuff,def,MAX_REG_BUFF);  
	}
	else {
		if (RegQueryValueEx(hKey, key, NULL, NULL, (UCHAR *)strbuff,
			&dsize) != ERROR_SUCCESS) {
			libpbc_myconfig_copystring(&strbuff,def,MAX_REG_BUFF);
		}
		RegCloseKey(hKey);
	}

	return strbuff;  /* Note that this must have been allocated by the calling process */
}


int libpbc_myconfig_getint(pool *p, const char *key, int def)
{
	char keyBuff[1024];
	HKEY hKey;
	UCHAR *dataBuff;
    int dsize, value;

	if (!(dataBuff = (UCHAR *)malloc(sizeof (DWORD)))) {
		fatal(p,"malloc failed in libpbc_myconfig_getint.",2);
	}
	dsize = sizeof(DWORD);
	strcpy (keyBuff,PBC_PUBKEY);  /* config. settings in main pubcookie service key */
	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		keyBuff,0,KEY_READ,&hKey) != ERROR_SUCCESS) {
		return def;  
	}
	
	if (RegQueryValueEx(hKey, key, NULL, NULL, dataBuff,
		&dsize) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return def;
	}

	value = (int)*dataBuff;
	free(dataBuff);
	RegCloseKey(hKey);
	return value;
}

int libpbc_myconfig_getswitch(pool *p, const char *key, int def)
{
	/* Unimplemented */
	return def;
}

char **libpbc_myconfig_getlist(pool *p, const char *key)
{
	/* Unimplemented */
	return NULL;
}

int libpbc_myconfig_init(pool *p, const char *alt_config, const char *ident)
{
		return TRUE;
}

char *AddSystemRoot(pool *p, char *buff,const char *subdir) 
{
	char strbuff[MAX_REG_BUFF];

	strncpy(buff, libpbc_config_sb_getstring(p, strbuff, "System_Root",""),MAX_PATH+1);
	if (strcmp(buff,"") == 0) {
		GetSystemDirectory(buff,MAX_PATH+1);
	}
	strncat(buff,subdir,MAX_PATH+1);
	return (buff);  //Note, must be allocated by calling process
}


#endif /*WIN32*/
