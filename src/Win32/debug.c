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

char Trace_Date[64];
char Instance[64];
char Debug_Dir[MAX_PATH];
FILE *debugFile=NULL;
int Debug_Trace = 0;
pool *p=NULL;


void pbc_vlog_activity( int logging_level, const char * format, va_list args )
{
    char      log[4096];
	HANDLE hEvent;
	PTSTR pszaStrings[1];

        
    if (logging_level <= (libpbc_config_getint(p,"logging_level", Debug_Trace)))    {
		
        _vsnprintf(log, sizeof(log)-1, format, args);
		pszaStrings[0] = log;
        hEvent = RegisterEventSource(NULL,"W3SVC");
		if (hEvent) 
		{
			ReportEvent(hEvent, EVENTLOG_ERROR_TYPE, 0, (DWORD)8675309, NULL, (WORD)1, 0,                  
                (const char **)pszaStrings, NULL);                   
			DeregisterEventSource(hEvent);
		}
		
		
  }
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


extern VOID OutputDebugMsg (char *buff)
{			
	time_t ltime;
	struct tm *today;
	char Todays_Date [64];

	// For debugger if used
	OutputDebugString(buff);

	if ( debugFile ) {
		// Open new trace file if this is a new day
		time(&ltime);
		today = localtime(&ltime);
		strftime(Todays_Date,64,"%Y%m%d\0",today);
		if (strcmp (Todays_Date,Trace_Date) != 0)
			Open_Debug_Trace ();

		fprintf(debugFile,"%s",buff);
		fflush(debugFile);
	}
}

VOID Close_Debug_Trace ()
{
	time_t ltime;

	if ( debugFile ) {

		time(&ltime);

		fclose(debugFile);

		debugFile = NULL;

	}
}


BOOL Open_Debug_Trace ()
{
    char szName[256], szBuff[1024];
	time_t ltime;
	struct tm *today;

//	DebugMsg((DEST,"Open_Debug_Trace\n"));  //debug


	time(&ltime);
	today = localtime(&ltime);

	strftime(Trace_Date,64,"%Y%m%d\0",today);
	sprintf(szBuff,"%s%s",Debug_Dir,Instance);
	sprintf(szName,"%s%s\\%s.log",Debug_Dir,Instance,Trace_Date);

	// Directory must exist else open will fail

	mkdir(szBuff);

	// output stats if file already open

	Close_Debug_Trace ();

	debugFile = fopen(szName, "a");

	if ( !debugFile ) {
		syslog(1,"[Open_Debug_Trace] Failed to open trace file %s",szName);
			}
	else
			syslog(1,"[Open_Debug_Trace] opened trace file %s",szName);

		
	DebugMsg((DEST, "\n**********************************************************************\n %s\n\n Opening Debug File %s\n\n",
		ctime(&ltime),szName));

	if ( debugFile ) 
		return TRUE;
	else
		return FALSE;
}
