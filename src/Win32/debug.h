//
//  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
//  For terms of use see doc/LICENSE.txt in this distribution.
//

//
//  $Id: debug.h,v 1.7 2003-08-07 04:17:20 ryanc Exp $
//

#include <windows.h>
#define DEST buff

#define DebugMsg(x)						\
	if (Debug_Trace) {					\
		char buff[4096];				\
		sprintf x;						\
		OutputDebugMsg(buff);			\
	}

void syslog(int whichlog, const char *message, ...);
VOID Close_Debug_Trace ();
BOOL Open_Debug_Trace ();
VOID OutputDebugMsg (char *buff);

extern char Instance[64];
extern char Debug_Dir[MAX_PATH];
extern char *SystemRoot;
extern FILE *debugFile;
extern int Debug_Trace;
