//
//  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
//  For terms of use see doc/LICENSE.txt in this distribution.
//

//
//  $Id: debug.h,v 1.8 2003-09-26 22:27:02 ryanc Exp $
//

#include <windows.h>

void syslog(int whichlog, const char *message, ...);
char * AddToLog(char*LogBuff, const char *format, ...);
void filter_log_activity ( const char * source, int logging_level, const char * format, va_list args );

extern char Instance[64];
extern char *SystemRoot;

//Message Event IDs

// MessageId: ERR_ONE
//
// MessageText:
//
//  Generic Error
//
#define PBC_ERR_ID_GENERIC                      0x00000001L

//
// MessageId: ERR_TWO
//
// MessageText:
//
//  Debug: %1
//
#define PBC_ERR_ID_DEBUG                        0x00000002L

//
// MessageId: ERR_THREE
//
// MessageText:
//
//  %1
//
#define PBC_ERR_ID_SIMPLE                       0x00000003L

#define LOGBUFFSIZE 4096
