
#define Pubcookie_Version "Pubcookie ISAPI Filter, 2.7"


char Instance[3];
char SystemRoot[MAX_PATH];
char Trace_Date[64];
char Debug_Dir[MAX_PATH];
// Default Debug Trace directory in %SystemRoot%
#define DEBUG_DIR	"\\system32\\LogFiles\\PubcookieFilter"

int  Ignore_Poll;     // Set to "1" to ignore Network Dispatcher "/" polls
char Web_Login[MAX_PATH];  // default is https://weblogin.washington.edu/
char Enterprise_Domain[MAX_PATH];  // default is ".washington.edu"
char Error_Page[MAX_PATH]; // Redirect user to this page on fatal errors

typedef struct {
	char				*g_certfile;
	char				*s_keyfile;
	char				*s_certfile;
	char				*crypt_keyfile;
	md_context_plus		*session_sign_ctx_plus;
	md_context_plus		*session_verf_ctx_plus;
	md_context_plus		*granting_verf_ctx_plus;
	crypt_stuff			*c_stuff;
	int					serial_s_sent;
	char				server_hostname[MAX_PATH];
	char				NTUserId[SF_MAX_USERNAME];
	char				Password[SF_MAX_PASSWORD];
	int					inact_exp;
	int					hard_exp;
	char				force_reauth[4];
	char				AuthType;
	DWORD				session_reauth;
	char				logout_dir[MAX_PATH];
	char				logout_redir_dir[MAX_PATH];

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
//	char		path_id[PBC_app_id_LEN];
	char		s_cookiename[64];
	char		creds;
	char		force_reauth[4];
	char		AuthType;
	char		default_url[1024];
	char		timeout_url[1024];
	char		user[PBC_USER_LEN];
	char		appsrvid[PBC_APPSRV_ID_LEN];
	char		appsrv_port[6];
	char		uri[2048];		              // *** size ??
	char		args[4096];                   // ***
	char		method[8];		              // ***
	char		handler;
	DWORD		session_reauth;
	DWORD		logout;  //todo needs to be moved out
	char		logout_dir[MAX_PATH];
	DWORD		logout_redir;  //todo needs to be moved out
	char		logout_redir_dir[MAX_PATH];

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

#define PUBKEY "System\\CurrentControlSet\\Services\\PubcookieFilter\\"
#define WINKEY "System\\CurrentControlSet\\Control\\Windows"
#define PBC_Header_Appid  "Pubcookie-Appid:"
#define PBC_Header_User   "Pubcookie-User:"
#define PBC_Header_Creds  "Pubcookie-Creds:"
#define PBC_Header_Server "Pubcookie-Server:"

#define PBC_CREDS_CRED1 '1'
#define PBC_CREDS_CRED2 '2'
#define PBC_CREDS_CRED3 '3'
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

#define PUBLIC (libpbc_config_getstring("PUBLIC_name", "PUBLIC")) 
#define NETID (libpbc_config_getstring("NETID_name", "UWNETID"))
#define SECURID (libpbc_config_getstring("SECURID_name", "SECURID"))
#define LOGOUT (libpbc_config_getstring("LOGOUT_name", "LOGOUT"))
#define LOGOUT_REDIR (libpbc_config_getstring("LOGOUT_REDIR_name", "LOGOUT_REDIR"))