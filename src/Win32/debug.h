#define DEST buff

#define DebugMsg(x)						\
	if (Debug_Trace) {					\
		char buff[4096];				\
		sprintf x;						\
		OutputDebugMsg(buff);			\
	}

void syslog(int whichlog, const char *message, ...);
void pbc_log_activity(int logging_level, const char *message,...);
void pbc_vlog_activity( int logging_level, const char * format, va_list args );
VOID Close_Debug_Trace ();
BOOL Open_Debug_Trace ();
VOID OutputDebugMsg (char *buff);

extern char Instance[64];
extern char Debug_Dir[MAX_PATH];
extern char *SystemRoot;
extern FILE *debugFile;
extern int Debug_Trace;
