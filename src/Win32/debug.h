//  DebugMsg() is used for debugging 
#define DEST buff
extern VOID OutputDebugMsg (char *buff);
extern int Debug_Trace;
extern FILE *debugFile;

#define DebugMsg(x)						\
	if (Debug_Trace) {					\
		char buff[4096];				\
		sprintf x;						\
		OutputDebugMsg(buff);			\
	}
extern void syslog(int whichlog, const char *message, ...);
extern void pbc_log_activity(int logging_level, const char *message,...);
