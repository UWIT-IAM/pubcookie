/*

    Copyright 1999-2002, University of Washington.  All rights reserved.
    see doc/LICENSE.txt for copyright information

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|

    All comments and suggestions to pubcookie@cac.washington.edu
    More information: http://www.pubcookie.org/
    Written by the Pubcookie Team

    this is the routines for the pubcookie configuration file .../config

 */

/*
    $Id: pbc_myconfig.c,v 1.22 2003-03-24 21:28:14 jjminer Exp $
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
#endif /* HAVE_SYSEXITS_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "pbc_config.h"
#include "pbc_myconfig.h"
#include "snprintf.h"
#include "pubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

extern int errno;

struct configlist {
    char *key;
    char *value;
};

static struct configlist *configlist;
static int nconfiglist;

static void config_read(pool *p, const char *alt_config);
static void fatal(pool *p, const char *s, int ex);

#ifndef WIN32

int libpbc_config_init(pool *p, const char *alt_config, const char *ident)
{
    const char *val;
    int umaskval = 0;
    
    config_read(p, alt_config);
    
    /* Look up umask */
    val = libpbc_config_getstring(p, "umask", "022");
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

const char *libpbc_config_getstring(pool *p, const char *key, const char *def)
{
    int opt;

    if ( key == NULL )
        return def;

    for (opt = 0; opt < nconfiglist; opt++) {
        if (configlist[opt].key == NULL ) {
            libpbc_abend( "Option key suddenly became NULL!  Somebody fudged a pointer!" );
        }
        if ( *key == configlist[opt].key[0] &&
            !strcmp(key, configlist[opt].key))
	    return configlist[opt].value;
    }
    return def;
}

/* output must be free'd.  (no subpointers should be free'd.) */
char **libpbc_config_getlist(pool *p, const char *key)
{
    const char *tval = libpbc_config_getstring(p, key, NULL);
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

int libpbc_config_getint(pool *p, const char *key, int def)
{
    const char *val = libpbc_config_getstring(p, key, (char *)0);
    
    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
        return def;
    return atoi(val);
}

int libpbc_config_getswitch(pool *p, const char *key, int def)
{
    const char *val = libpbc_config_getstring(p, key, (char *)0);

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
static void config_read(pool *p, const char *alt_config)
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *ptr, *q, *key;
    
    infile = pbc_fopen(p, alt_config ? alt_config : PBC_CONFIG, "r");
    if (!infile) {
        snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
                 alt_config ? alt_config : PBC_CONFIG,
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
		     "invalid option name on line %d of configuration file",
		     lineno);
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
                     "empty option value on line %d of configuration file",
                     lineno);
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

#else /*WIN32*/

/* Windows registry functions added by Ryan Campbell */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <pem.h>
#include <httpfilt.h>

#include <../debug.h>

#define CONFIGLISTGROWSIZE 50




const char *libpbc_config_getstring(pool *p, const char *key, const char *def)
{
    int opt;
    
    for (opt = 0; opt < nconfiglist; opt++) {
        if (!stricmp(key, configlist[opt].key))
	    return configlist[opt].value;
    }
    return def;
}


int libpbc_config_getint(pool *p, const char *key, int def)
{
    const char *val = libpbc_config_getstring(p, key, (char *)0);
    
    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
        return def;
    return atoi(val);
}


int libpbc_config_init(pool *p, const char *alt_config, const char *ident)
{
	int rslt;
	HKEY hKey;
	char keyBuff[1024];
	DWORD dwkey,dwdata,type;
    int alloced = 0;
	char dataBuff[2048],fmtstr[34];

	nconfiglist = 0;
	strcpy (keyBuff,PBC_PUBKEY);  //config. settings in main pubcookie service key

	if (rslt = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		keyBuff,0,KEY_READ,&hKey) != ERROR_SUCCESS) {
		return TRUE;  //It's OK if the key doesn't exist yet
	}

	DebugMsg((DEST,"Config. Values:\n"));  //Won't work if Debug_Trace is off

	while (1) {
		if (nconfiglist == alloced) {
            alloced += CONFIGLISTGROWSIZE;
            configlist = (struct configlist *)
                realloc((char *)configlist, alloced*sizeof(struct configlist));
            if (!configlist) {
				RegCloseKey (hKey);
				return FALSE;
            }
		}
		
		dwkey =sizeof(keyBuff);
		dwdata=sizeof(dataBuff);
		if (RegEnumValue(hKey,nconfiglist,keyBuff,&dwkey,NULL,&type,dataBuff,&dwdata) == ERROR_SUCCESS) {
			
			
			configlist[nconfiglist].key = pbc_strdup(p, keyBuff);
			if (!configlist[nconfiglist].key) {
				RegCloseKey (hKey);
				return FALSE;
			}
			
			switch (type) {

			case REG_SZ:
				
				configlist[nconfiglist].value = pbc_strdup(p, dataBuff);
				if (!configlist[nconfiglist].value) {
					RegCloseKey (hKey);
					return FALSE;
				}
				DebugMsg((DEST,"                %-20s= %s\n",configlist[nconfiglist].key,configlist[nconfiglist].value));
				break;
				
			case REG_DWORD: //store DWORD as string for function spec. compatability
				configlist[nconfiglist].value = pbc_strdup(p, itoa((DWORD)*dataBuff,fmtstr,10));
				if (!configlist[nconfiglist].value) {
					RegCloseKey (hKey);
					return FALSE;
				}
				DebugMsg((DEST,"                %-20s= %d\n",configlist[nconfiglist].key,(DWORD)dataBuff));
				break;
				
			default:
				break;

			}


			nconfiglist++;
			
		}
		else {  //RegEnumKeyValue != ERROR_SUCCESS; we're done.
			RegCloseKey (hKey);
			return TRUE;
		}
	}
}

extern char *SystemRoot;

const char *AddSystemRoot(const char *subdir) 
{
	static char *buff=NULL;

	buff = (char*)realloc(buff,(MAX_PATH+1));
	strcpy(buff,SystemRoot);
	strcat(buff,subdir);
	return (buff);

}
#endif /*WIN32*/
