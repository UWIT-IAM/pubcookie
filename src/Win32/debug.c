//
//  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
//  For terms of use see doc/LICENSE.txt in this distribution.
//

//
//  $Id: debug.c,v 1.10 2003-09-26 22:27:02 ryanc Exp $
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>

typedef void pool;


#include <pem.h>
#include "../pubcookie.h"
#include "../libpubcookie.h"
#include "../pbc_config.h"
#include "../pbc_version.h"
#include "../pbc_myconfig.h"
#include "../pbc_configure.h"
#include "debug.h"

pool *p=NULL;

#define BUFFSIZE 4096

extern void filter_log_activity ( const char * source, int logging_level, const char * format, va_list args )
{

    char      log[BUFFSIZE];
	HANDLE hEvent;
	PTSTR pszaStrings[1];
	unsigned short errortype;
	DWORD eventid=PBC_ERR_ID_SIMPLE;

    if (logging_level <= (libpbc_config_getint(p,"Debug_Trace", LOG_WARN)))    {
		
		switch (logging_level) {
		case LOG_INFO:
            errortype = EVENTLOG_INFORMATION_TYPE;
            break;
		case LOG_DEBUG:
            errortype = EVENTLOG_INFORMATION_TYPE;
			eventid = PBC_ERR_ID_DEBUG;
            break;
		case LOG_ERR:
            errortype = EVENTLOG_ERROR_TYPE;
			break;
		case LOG_WARN:
		default:
			errortype = EVENTLOG_WARNING_TYPE;
			
		}
        _vsnprintf(log, BUFFSIZE, format, args);
		pszaStrings[0] = log;
        hEvent = RegisterEventSource(NULL,source);
		if (hEvent) 
		{
			ReportEvent(hEvent, errortype, 0, eventid, NULL, (WORD)1, 0,                  
                (const char **)pszaStrings, NULL);                   
			DeregisterEventSource(hEvent);
		}
	}


}

void pbc_vlog_activity( int logging_level, const char * format, va_list args )
{
	filter_log_activity ("Pubcookie", logging_level, format, args);
}

extern void syslog(int whichlog, const char *message, ...) {

    va_list   args;

    va_start(args, message);

    pbc_vlog_activity( whichlog, message, args );

    va_end(args);

}
extern void pbc_log_activity(pool *p, int logging_level, const char *message,...)
{
    va_list   args;

    va_start(args, message);

    pbc_vlog_activity( logging_level, message, args );

    va_end(args);
}

char * AddToLog(char*LogBuff, const char *format, ...) {
	char *LogPos;

	va_list   args;

    va_start(args, format);

	LogPos = LogBuff + strlen(LogBuff);

    _vsnprintf(LogPos, LOGBUFFSIZE - (LogPos - LogBuff), format, args);

    va_end(args);

    return (LogBuff);
}


