// Windows implementation of ../pbc_myconfig.c
// Windows registry functions added by
// Ryan Campbell


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <pem.h>
#include <httpfilt.h>


#include "../pbc_myconfig.h"
#include "../pbc_config.h"
#include "../pubcookie.h"
#include "PubCookieFilter.h"



#define CONFIGLISTGROWSIZE 50

struct configlist {
    char *key;
    char *value;
};

static struct configlist *configlist;
static int nconfiglist;

const char *libpbc_config_getstring(const char *key, const char *def)
{
    int opt;
    
    for (opt = 0; opt < nconfiglist; opt++) {
        if (*key == configlist[opt].key[0] &&
            !strcmp(key, configlist[opt].key))
	    return configlist[opt].value;
    }
    return def;
}


int libpbc_config_getint(const char *key, int def)
{
    const char *val = libpbc_config_getstring(key, (char *)0);
    
    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
        return def;
    return atoi(val);
}


int libpbc_config_init(const char *alt_config, const char *ident)
{
	int rslt;
	HKEY hKey;
	char keyBuff[1024];
	DWORD dwkey,dwdata,type;
    int alloced = 0;
	char dataBuff[2048],fmtstr[34];

	nconfiglist = 0;
	strcpy (keyBuff,PUBKEY);  //config. settings in main pubcookie service key

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
			
			
			configlist[nconfiglist].key = strdup(keyBuff);
			if (!configlist[nconfiglist].key) {
				RegCloseKey (hKey);
				return FALSE;
			}
			
			switch (type) {

			case REG_SZ:
				
				configlist[nconfiglist].value = strdup(dataBuff);
				if (!configlist[nconfiglist].value) {
					RegCloseKey (hKey);
					return FALSE;
				}
				DebugMsg((DEST,"                %-20s= %s\n",configlist[nconfiglist].key,configlist[nconfiglist].value));
				break;
				
			case REG_DWORD: //store DWORD as string for function spec. compatability
				
				configlist[nconfiglist].value = strdup(itoa((DWORD)dataBuff,fmtstr,10));
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
