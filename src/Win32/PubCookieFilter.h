
#define Pubcookie_Version "Pubcookie ISAPI Filter, 3.0.0 pre-beta4"


typedef struct {
	char				*g_certfile;
	char				*s_keyfile;
	char				*s_certfile;
	char				*crypt_keyfile;
	int					serial_s_sent;
	char				server_hostname[MAX_PATH];
} pubcookie_server_rec;

typedef struct {
	char		remote_host[MAX_PATH];
	int			inact_exp;
	int			hard_exp;
	int			failed;
	int			has_granting;
	char		pszUser[SF_MAX_USERNAME];
	char		pszPassword[SF_MAX_PASSWORD];
	char		appid[PBC_APP_ID_LEN];
	char		s_cookiename[64];
	char		force_reauth[4];
	char		AuthType;
	char		default_url[1024];
	char		timeout_url[1024];
	char		user[PBC_USER_LEN];
	char		appsrvid[PBC_APPSRV_ID_LEN];
	char		appsrv_port[6];
	char		uri[1024];		              // *** size ??
	char		args[4096];                   // ***
	char		method[8];		              // ***
	char		handler;
	DWORD		session_reauth;
	DWORD		logout_action;
	char		Error_Page[MAX_PATH];
	char		Enterprise_Domain[1024];
	char		Web_Login[1024];
    pbc_cookie_data *cookie_data;


} pubcookie_dir_rec;

DWORD Notify_Flags;

pubcookie_server_rec scfg;

// One lock to protect all three global ctx_plus structures
// session_sign_ctx_plus  session_verf_ctx_plus  granting_verf_ctx_plus
// libpbc cookie routines scribble on .._ctx_plus->ctx 

CRITICAL_SECTION Ctx_Plus_CS;

// Statistic variables

unsigned int Total_Requests;
unsigned int Max_Url_Length;
unsigned int Max_Query_String;
unsigned int Max_Content_Length;
unsigned int Max_Cookie_Size;
unsigned int Max_Bytes_Sent;
unsigned int Max_Bytes_Recvd;

#define START_COOKIE_SIZE  1024
#define MAX_COOKIE_SIZE	   10500	// allow enough room for 20 session cookies
									// browser limits 20 cookies per server

// From /usr/local/src/apache_1.2.0/src/httpd.h

#define DECLINED -1             /* Module declines to handle */
#define OK		  0             /* Module has handled this stage. */


#define DEST buff
#define MAX_DEBUG_SIZE 4096

//  DebugMsg() is used for debugging 
//  use sprintf instead of wsprintf so we can use things line "%.*s"

#define DebugMsg(x)						\
	if (Debug_Trace) {					\
		char buff[4096];				\
		sprintf x;						\
		OutputDebugMsg(buff);			\
	}


#define DebugFlush						\
	{									\
	if ( debugFile )					\
		fflush(debugFile);				\
	}
extern VOID OutputDebugMsg (char *buff);
extern int Debug_Trace;
extern FILE *debugFile;
void vlog_activity( int logging_level, const char * format, va_list args );
char *Get_Cookie (HTTP_FILTER_CONTEXT* pFC, char *name);



#define PUBKEY "System\\CurrentControlSet\\Services\\PubcookieFilter\\"
#define WINKEY "System\\CurrentControlSet\\Control\\Windows"
#define PBC_Header_Appid   "Pubcookie-Appid:"
#define PBC_Header_User    "Pubcookie-User:"
#define PBC_Header_Creds   "Pubcookie-Creds:"
#define PBC_Header_Server  "Pubcookie-Server:"
#define PBC_Header_Version "Pubcookie-Filter-Version:"

// Define COOKIE_PATH to include a path of /<application name> in the session
// cookie. This implies that the first node of all URLs are case sensative since
// browsers will only return cookies if the URL matches the path exactly.
// This path feature is desireable so the browser doesn't return all session
// cookies for all applications visited for every URL. 
// Setting this option requires that the Default and Timeout URLs defined in the
// registry are case sensative also.

// Pubcookie Version a5 got rid of these, I still like em!

#define PBC_BAD_GRANTING_CERT 4
#define PBC_BAD_SESSION_CERT 5
#define PBC_BAD_VERSION 6
#define PBC_BAD_APPID 7
#define PBC_BAD_SERVERID 8
// used to redirect from http->https
#define PBC_BAD_PORT 9
#define PBC_LOGOUT_REDIR 10

#define PBC_DEFAULT_KEY "default"

//AUTH Types = Cred Types
#define AUTH_NONE '0'
#define AUTH_NETID '1'
#define AUTH_SECURID '3'


//LOGOUT Types

#define LOGOUT_NONE 0
#define LOGOUT_LOCAL 1  //NOTE: overrides AuthType to PUBLIC
#define LOGOUT_REDIRECT 2
#define LOGOUT_REDIRECT_CLEAR_LOGIN 3
