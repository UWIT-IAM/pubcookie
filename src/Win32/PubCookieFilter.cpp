//
//  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
//  For terms of use see doc/LICENSE.txt in this distribution.
//

//
//  $Id: PubCookieFilter.cpp,v 1.23 2003-12-17 22:10:56 ryanc Exp $
//

//#define COOKIE_PATH

#include <windows.h>
#include <stdio.h>
#include <direct.h>       // For mkdir
#include <time.h>
#include <process.h>
// #include <shfolder.h>  // For System Path, in Platform SDK
#include <httpfilt.h>

typedef void pool;

extern "C" 
{
#include <pem.h>
#include "../pubcookie.h"
#include "../libpubcookie.h"
#include "../pbc_config.h"
#include "../pbc_version.h"
#include "../pbc_myconfig.h"
#include "../pbc_configure.h"
#include "PubCookieFilter.h"
#include "debug.h"
}

pool *p=NULL;

#define HDRSIZE 56

VOID filterlog(pubcookie_dir_rec *dcfg, int loglevel, const char *format, ...) {
	char source[HDRSIZE];

	va_list   args;

    va_start(args, format);
	_snprintf(source,HDRSIZE,"Pubcookie-%s",dcfg->instance_id);

    filter_log_activity ( source, loglevel, format, args );

    va_end(args);
}

bool logsource_exists(const char *source) {

	HKEY hKey;
	UCHAR *DataBuff;
	DWORD dsize;
	DWORD retval;
	char SystemRootBuff[MAX_PATH+1];
	char strbuff[MAX_REG_BUFF];
	
	if (!(DataBuff = (UCHAR *)malloc(MAX_REG_BUFF))) {
		syslog(LOG_ERR,"Malloc failed in logsource_exists");
		return FALSE;
	}
	
	//First, check to see if key exists
	dsize = MAX_REG_BUFF;
	_snprintf(strbuff,MAX_REG_BUFF,"System\\CurrentControlSet\\Services\\Eventlog\\Application\\%s",source);
	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		strbuff,0,KEY_READ,&hKey) != ERROR_SUCCESS) {
		return FALSE;
	}
	
	//Then, make sure the Event Message File is the current one
	AddSystemRoot(p, SystemRootBuff,"\\inetsrv\\pubcookie\\pbc_messages.dll");
		
	if (retval = RegQueryValueEx(hKey, "EventMessageFile", NULL, NULL, DataBuff, &dsize)) {
		retval = strncmp((char *)DataBuff, SystemRootBuff, MAX_PATH);
	}
	RegCloseKey(hKey);
	free(DataBuff);
	
	if (retval != 0) {
		return FALSE;
	}
	
	return TRUE;



}

bool SetRegDWORD (HKEY hKey, LPCTSTR value, const DWORD setDWORD)
{
	DWORD	dtype;
	DWORD	dsize;
	DWORD	retCode;
	
	
	dsize=sizeof(setDWORD);
	dtype=REG_DWORD;
	
	retCode = RegSetValueEx(hKey, value, NULL, dtype, (const UCHAR*)&setDWORD, dsize);
	if (retCode != ERROR_SUCCESS) {
  //      printerror(retCode);
		return (false);
	}
	
	return (true);
	
}

bool SetRegString (HKEY hKey, LPCTSTR value, LPCTSTR setstr)
{
	DWORD	dtype;
	DWORD	dsize;
	DWORD	retCode;
	
	
	dsize=strlen(setstr);
	dtype=REG_SZ;
	
	retCode = RegSetValueEx(hKey, value, NULL, dtype, (const UCHAR *)setstr, dsize);
	if (retCode != ERROR_SUCCESS) {
		return (false);
	}
	
	return (true);
	
}

VOID create_source(const char *source) {
	char keybuff[MAX_REG_BUFF];
	HKEY hKey;
	UCHAR *dataBuff;
	int dsize;
	char SystemRootBuff[MAX_PATH+1];
	DWORD retval;

	if (!(dataBuff = (UCHAR *)malloc(MAX_REG_BUFF))) {
		syslog(LOG_ERR,"Malloc failed in create_source");
		return;
	}

	dsize = MAX_REG_BUFF;
	_snprintf(keybuff,MAX_REG_BUFF,"System\\CurrentControlSet\\Services\\Eventlog\\Application\\%s",source);

	if ((retval = RegCreateKeyEx(HKEY_LOCAL_MACHINE, 
					keybuff,
					NULL,NULL,NULL,
					KEY_ALL_ACCESS,
					NULL,
					&hKey,
					NULL)) != ERROR_SUCCESS) {
		char fmtstr[512];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,NULL,retval,0,fmtstr,512,NULL);
		syslog(LOG_ERR,"Cannot create logging source: %s\nError Message: %s",keybuff,fmtstr);
	}

	SetRegString(hKey,"EventMessageFile", AddSystemRoot(p, SystemRootBuff,"\\inetsrv\\pubcookie\\pbc_messages.dll"));
	SetRegDWORD(hKey,"TypesSupported",7);

	RegCloseKey(hKey);


}

/**
 * get a random int used to bind the granting cookie and pre-session
 * @returns random int or -1 for error
 * but, what do we do about that error?
 */
int get_pre_s_token(HTTP_FILTER_CONTEXT* pFC) {
    int i;
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;


    if( (i = libpbc_random_int(p)) == -1 ) {
        filterlog(dcfg, LOG_ERR,	"get_pre_s_token: OpenSSL error");
    }

		filterlog(dcfg, LOG_INFO, "get_pre_s_token: token is %d\n", i);
    return(i);

}


int get_pre_s_from_cookie(HTTP_FILTER_CONTEXT* pFC)
{
    pubcookie_dir_rec   *dcfg;
    pbc_cookie_data     *cookie_data = NULL;
    char 		*cookie = NULL;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

    if( (cookie = Get_Cookie(pFC, PBC_PRE_S_COOKIENAME)) == NULL )

        filterlog(dcfg, LOG_ERR,	"get_pre_s_from_cookie: no pre_s cookie, uri: %s\n", dcfg->uri);
    else
		cookie_data = libpbc_unbundle_cookie(p, cookie, dcfg->server_hostname, false);

    if( cookie_data == NULL ) {
        filterlog(dcfg, LOG_ERR, "get_pre_s_from_cookie: can't unbundle pre_s cookie uri: %s\n", dcfg->uri);
	dcfg->failed = PBC_BAD_AUTH;
	return -1;
    }
 
    return((*cookie_data).broken.pre_sess_token);

}

VOID Clear_Cookie(HTTP_FILTER_CONTEXT* pFC, char* cookie_name, char* cookie_domain, char* cookie_path, bool secure)
{

	char new_cookie[START_COOKIE_SIZE];
	char secure_string[16];
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if (secure) {
		strncpy (secure_string,"; secure",15);
	}
	else {
		strncpy (secure_string,"",15);
	}

	sprintf(new_cookie, "Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s%s\r\n", 
			cookie_name,
			PBC_CLEAR_COOKIE,
			cookie_domain, 
			cookie_path,
			EARLIEST_EVER,
			secure_string);

	
		pFC->AddResponseHeaders(pFC,new_cookie,0);

		filterlog(dcfg, LOG_INFO,"  Cleared Cookie %s\n",cookie_name);
}

int Redirect(HTTP_FILTER_CONTEXT* pFC, char* RUrl) {
    char    szBuff[2048];
	DWORD	dwBuffSize;
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

    sprintf(szBuff,"Content-Type: text/html\r\n");
		
	filterlog(dcfg, LOG_INFO," Redirect to %s",RUrl);

	pFC->AddResponseHeaders(pFC,szBuff,0);

	pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
		"200 OK",NULL,NULL);
		
    sprintf(szBuff, "<HTML>\n"
					" <HEAD>\n"
					"  <meta HTTP-EQUIV=\"Refresh\" CONTENT=\"%d;URL=%s\">\n"
					" </HEAD>\n"
					" <BODY BGCOLOR=\"#FFFFFF\">\n"
					" </BODY>\n"
					"</HTML>\n"		
					,PBC_REFRESH_TIME, RUrl);
	
	dwBuffSize=strlen(szBuff);

	pFC->WriteClient (pFC, szBuff, &dwBuffSize, 0);

	return OK;

}

BOOL Pubcookie_Init () 
{
	int rslt;

	// Need TCPIP for gethostname stuff
	   
	WSADATA wsaData;

	libpbc_config_init(p,"","");

	syslog(LOG_INFO,"Pubcookie_Init\n  %s\n",Pubcookie_Version);
	
	if ( rslt = WSAStartup((WORD)0x0101, &wsaData ) ) 
	{
		syslog(LOG_ERR,"[Pubcookie_Init] Unable to initialize WINSOCK: %d",rslt);
		return FALSE;
	}

	// Initialize Pubcookie Stuff

	if (!libpbc_pubcookie_init(p)) {
		return FALSE;
	}

    return TRUE;

}  /* Pubcookie_Init */

// 'X' out the pubcookie cookies so the web page can't see them.
void Blank_Cookie (HTTP_FILTER_CONTEXT* pFC,
				   HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo,
				   char *name) 
{
	char cookie_data[MAX_COOKIE_SIZE+1]; 
	char *cookie;
	char *ptr;
	char name_w_eq[256];
	int pos;
	DWORD cbSize, dwError;
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO," Blank_Cookie\n"); 

	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pHeaderInfo->GetHeader(pFC,"Cookie:",cookie_data,&cbSize)) {
		dwError = GetLastError();
		filterlog(dcfg, LOG_INFO," GetHeader[Cookie:] failed = %d (%x), buffer size= %d\n",
			dwError,dwError,cbSize);
		return;
	}

	/* add an equal on the end if not session cookie*/
	strcpy(name_w_eq,name);
	if ( strcmp(name, PBC_S_COOKIENAME) != 0 )
		strcat(name_w_eq,"=");

	ptr = cookie_data;

	while (*ptr) {

	if (!(cookie = strstr(ptr, name_w_eq)))
		break;

	cookie += strlen(name_w_eq);

	if ( strcmp(name, PBC_S_COOKIENAME) == 0 ) {
		pos = strcspn(cookie,"=;");
		ptr = cookie + pos + 1;
	}
	else
		ptr = cookie;

	while(*ptr) {
		if (*ptr == ';')
			break;
		*ptr = PBC_X_CHAR;
		ptr++;
	}

	if (*ptr)
		ptr ++;
	}

	pHeaderInfo->SetHeader(pFC,"Cookie:",(char *)cookie_data);

}  /* Blank_Cookie */


int Hide_Cookies (HTTP_FILTER_CONTEXT* pFC,
					  HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO," Hide_Cookies\n");

	Blank_Cookie(pFC, pHeaderInfo, PBC_S_COOKIENAME);
    Blank_Cookie(pFC, pHeaderInfo, PBC_G_COOKIENAME);

    return OK;

} /* Hide_Cookies */



void Add_No_Cache(HTTP_FILTER_CONTEXT* pFC)
{
	char			szHeaders[PBC_1K];

	sprintf(szHeaders, 
			"Cache-Control: no-cache\r\n"
			"Pragma: no-cache\r\n"
			"Expires: %s\r\n", EARLIEST_EVER);
			
		  
	pFC->AddResponseHeaders(pFC,szHeaders,0);

}
void Add_Cookie (HTTP_FILTER_CONTEXT* pFC, char* cookie_name, unsigned char* cookie_contents, char* cookie_domain)
{
	char			szHeaders[PBC_1K];
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO,"  Adding cookie %s\n   domain=%s;\n   path=/;\n   secure;\n",cookie_name,cookie_domain);

	snprintf(szHeaders, PBC_1K, "Set-Cookie: %s=%s; domain=%s; path=/; secure\r\n",
		cookie_name, 
		cookie_contents,
		cookie_domain);

	pFC->AddResponseHeaders(pFC,szHeaders,0);

}

int Auth_Failed (HTTP_FILTER_CONTEXT* pFC) 
{
	char 			args[PBC_4K];
	char 			g_req_contents[PBC_4K];
	unsigned char	e_g_req_contents[PBC_4K];
	char			szTemp[PBC_1K];
    unsigned char   *pre_s;
	int				pre_sess_tok;

	pubcookie_dir_rec* dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO," Auth_Failed\n");

	/* reset these dippy flags */
	dcfg->failed = 0;

	/* deal with GET args */
	if ( strlen(dcfg->args) > 0 ) {
		if ( strlen(dcfg->args) > sizeof(args) ) {  // ?? does base64 double size ??
			filterlog(dcfg, LOG_ERR,"[Pubcookie_Init] Invalid Args Length = %d; remote_host: %s",
				strlen(dcfg->args), dcfg->remote_host);
			strcpy(args, "");
		} else
			libpbc_base64_encode(p, (unsigned char *)dcfg->args, (unsigned char *)args,
						strlen(dcfg->args));
		}
	else
		strcpy(args, "");

	strcpy(szTemp,dcfg->appsrvid);
	if ( strlen(dcfg->appsrv_port) > 0 ) {
		strcat(szTemp,":");
		strcat(szTemp,dcfg->appsrv_port);
	}
    if( (pre_sess_tok=get_pre_s_token(pFC)) == -1 ) {
		filterlog(dcfg, LOG_ERR,"Security Warning:  Unable to randomize pre-session cookie!");
        return(OK);
    }

  
	
	/* make the granting request */
	sprintf(g_req_contents, 
		"%s=%s&%s=%s&%s=%c&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%d&%s=%d", 
		PBC_GETVAR_APPSRVID,
		  dcfg->server_hostname,   // Need full domain name 
		PBC_GETVAR_APPID,
		  dcfg->appid,
		PBC_GETVAR_CREDS, 
		  dcfg->AuthType, 
		PBC_GETVAR_VERSION, 
		  PBC_VERSION, 
		PBC_GETVAR_METHOD, 
		  dcfg->method, 
		PBC_GETVAR_HOST, 
		  szTemp,
		PBC_GETVAR_URI, 
		  dcfg->uri,
		PBC_GETVAR_ARGS, 
		  args,
		PBC_GETVAR_SESSION_REAUTH,
		  dcfg->session_reauth,
		PBC_GETVAR_PRE_SESS_TOK,
		  pre_sess_tok);


	libpbc_base64_encode(p, (unsigned char *)g_req_contents, (unsigned char *)e_g_req_contents,
				strlen(g_req_contents));

	Add_Cookie(pFC, PBC_G_REQ_COOKIENAME, e_g_req_contents, dcfg->Enterprise_Domain);

	/* make the pre-session cookie */
    pre_s = libpbc_get_cookie(  
		p,
		(unsigned char *) "presesuser",
		PBC_COOKIE_TYPE_PRE_S, 
		PBC_CREDS_NONE, 
		pre_sess_tok,
		(unsigned char *)dcfg->server_hostname, 
		(unsigned char *)dcfg->appid,
		dcfg->server_hostname,
		0);
	
    Add_Cookie (pFC,PBC_PRE_S_COOKIENAME,pre_s,dcfg->appsrvid);
	
	Add_No_Cache(pFC);

	return (Redirect(pFC,dcfg->Login_URI));

}  /* Auth_Failed */


int Bad_User (HTTP_FILTER_CONTEXT* pFC)
{
	char szTemp[1024];
	DWORD dwSize;
	pubcookie_dir_rec* dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;


	filterlog(dcfg, LOG_INFO," Bad_User\n"); 

	if ( strlen(dcfg->Error_Page) == 0 ) {

		pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
								"200 OK",NULL,NULL);

		sprintf(szTemp,"<B> User Authentication Failed!<br><br>"
			           " Please contact <a href=\"mailto:ntadmin@%s\">ntadmin@%s</a> </B> <br>",
			dcfg->server_hostname,dcfg->server_hostname);
		dwSize=strlen(szTemp);

		pFC->WriteClient (pFC, szTemp, &dwSize, 0);

	} else {
		Redirect(pFC, dcfg->Error_Page);
	}

	return OK;

}  /* Bad_User */


int Is_Pubcookie_Auth (pubcookie_dir_rec *dcfg)
{
	if ( dcfg->AuthType != AUTH_NONE ) {
		filterlog(dcfg, LOG_INFO," Is_Pubcookie_Auth: True");
		return TRUE;
	}
	else {
		filterlog(dcfg, LOG_INFO," Is_Pubcookie_Auth: False");
		return FALSE;
	}

}  /* Is_Pubcookie_Auth */


/* a is from the cookie                                                       */
/* b is from the module                                                       */
int Pubcookie_Check_Version (HTTP_FILTER_CONTEXT* pFC, unsigned char *a, unsigned char *b) 
{
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_DEBUG," Pubcookie_Check_Version\n");

	if ( a[0] == b[0] && a[1] == b[1] )
		return 1;
	if ( a[0] == b[0] && a[1] != b[1] ) {
		filterlog(dcfg, LOG_ERR,"[Pubcookie_Check_Version] Minor version mismatch cookie: %s your version: %s", a, b);
		return 1;
	}

	return 0;

}  /* Pubcookie_Check_Version */


/* check and see if whatever has timed out                                    */
int Pubcookie_Check_Exp(HTTP_FILTER_CONTEXT* pFC, time_t fromc, int exp)
{
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( (fromc + exp) > time(NULL) ) {
		filterlog(dcfg, LOG_INFO," Pubcookie_Check_Exp: True");
		return 1;
	}
	else {
		filterlog(dcfg, LOG_INFO," Pubcookie_Check_Exp: False");
		return 0;
	}

}  /* Pubcookie_Check_Exp */


char *Get_Cookie (HTTP_FILTER_CONTEXT* pFC, char *name)
{

	char *cookie_header;
	char cookie_data[MAX_COOKIE_SIZE+1];
	char name_w_eq [256];
	char *cookie, *ptr;
	DWORD cbSize, dwError;
    pubcookie_dir_rec   *dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pFC->GetServerVariable(pFC,"HTTP_COOKIE",cookie_data,&cbSize)) {
		dwError = GetLastError();
		filterlog(dcfg, LOG_DEBUG," GetServerVariable[HTTP_COOKIE] failed = %d (%x), buffer size= %d\n",
			dwError,dwError,cbSize);
		if ( dwError == ERROR_INSUFFICIENT_BUFFER) {  // Should quit if too much cookie
			filterlog(dcfg, LOG_ERR,"[Get_Cookie] Cookie Data too large : %d", cbSize);
	//		return ERROR_INSUFFICIENT_BUFFER
		}
	//	else	
		return NULL;
	}

    /* add an equal on the end of cookie name */
	strcpy(name_w_eq,name);
	strcat(name_w_eq,"=");

	filterlog(dcfg, LOG_DEBUG,"  Looking for cookie name '%s' in (%d) (first 3000 bytes)\n%.3000s\n",
		name_w_eq,strlen(cookie_data),cookie_data);

	/* find the one that's pubcookie */

    if (!(cookie_header = strstr(cookie_data, name_w_eq))) {

		filterlog(dcfg, LOG_INFO, " Get_Cookie: %s : Not Found",name);
		return NULL;
	}
	cookie_header += strlen(name_w_eq);

	ptr = cookie_header;
	while(*ptr) {
		if (*ptr == ';')
			*ptr = 0;
		ptr++;
	}
	
    cookie = (char *)pbc_malloc(p, strlen(cookie_header)+1);
	if (!cookie) {
		filterlog(dcfg, LOG_ERR,"[Get_Cookie] Error allocating memory");
		return NULL;
	}

	strcpy(cookie,cookie_header);

//	Blank_Cookie (name);   // Why Blank it ??

		filterlog(dcfg, LOG_INFO, " Get_Cookie: %s : Found",name);

	return cookie;

}  /* Get_Cookie */

void Read_Reg_Values (char *key, pubcookie_dir_rec* dcfg)
{
	HKEY hKey;
	DWORD dwRead;
	long rslt;
	char authname[512];
	char strbuff[MAX_REG_BUFF];

	if (rslt = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		key,0,KEY_READ,&hKey) == ERROR_SUCCESS)
	{
		dwRead = sizeof (dcfg->pszUser);
		RegQueryValueEx (hKey, "NTUserId",
			NULL, NULL, (LPBYTE) dcfg->pszUser, &dwRead);
		
		dwRead = sizeof (dcfg->pszPassword);
		RegQueryValueEx (hKey, "Password", 
			NULL, NULL, (LPBYTE) dcfg->pszPassword, &dwRead);
		
		dwRead = sizeof (dcfg->inact_exp);
		RegQueryValueEx (hKey, "Inactive_Timeout",
			NULL, NULL, (LPBYTE) &dcfg->inact_exp, &dwRead);
		
		dwRead = sizeof (dcfg->hard_exp);
		RegQueryValueEx (hKey, "Hard_Timeout",
			NULL, NULL, (LPBYTE) &dcfg->hard_exp, &dwRead);
		
		dwRead = sizeof (dcfg->force_reauth);
		RegQueryValueEx (hKey, "Force_Reauth",
			NULL, NULL, (LPBYTE) dcfg->force_reauth, &dwRead);
		
		dwRead = sizeof (dcfg->session_reauth);
		RegQueryValueEx (hKey, "Session_Reauth",
			NULL, NULL, (LPBYTE) &dcfg->session_reauth, &dwRead);
		
		dwRead = sizeof (dcfg->logout_action);
			RegQueryValueEx (hKey, "Logout_Action",
							 NULL, NULL, (LPBYTE) &dcfg->logout_action, &dwRead);
		
		dwRead = sizeof (authname); authname[0] = NULL;
		RegQueryValueEx (hKey, "AuthType",
			NULL, NULL, (LPBYTE) authname, &dwRead);
		if ( strlen(authname) > 0 ) {
			if ( stricmp(authname,(PBC_AUTHTYPE1)) == 0 ) 
				dcfg->AuthType = AUTH_NETID;
			else
				if ( stricmp(authname,(PBC_AUTHTYPE3))== 0 ) 
					dcfg->AuthType = AUTH_SECURID;
				else
					if ( stricmp(authname,(PBC_AUTHTYPE0)) == 0 )
						dcfg->AuthType = AUTH_NONE;
		}

		dwRead = sizeof (dcfg->default_url);
		RegQueryValueEx (hKey, "Default_Url",
			NULL, NULL, (LPBYTE) dcfg->default_url, &dwRead);
		
		dwRead = sizeof (dcfg->timeout_url);
		RegQueryValueEx (hKey, "Timeout_Url",
			NULL, NULL, (LPBYTE) dcfg->timeout_url, &dwRead);
		
		dwRead = sizeof (dcfg->Login_URI);
		RegQueryValueEx (hKey, "Web_Login",
			NULL, NULL, (LPBYTE) dcfg->Login_URI, &dwRead);
		RegQueryValueEx (hKey, "Login_URI",
			NULL, NULL, (LPBYTE) dcfg->Login_URI, &dwRead);

		dwRead = sizeof (dcfg->Enterprise_Domain);
		RegQueryValueEx (hKey, "Enterprise_Domain",
			NULL, NULL, (LPBYTE) dcfg->Enterprise_Domain, &dwRead);
		dwRead = sizeof (dcfg->Error_Page);
		RegQueryValueEx (hKey, "Error_Page",
			NULL, NULL, (LPBYTE) dcfg->Error_Page, &dwRead);
		dwRead = sizeof (dcfg->Set_Server_Values);
		RegQueryValueEx (hKey, "SetHeaderValues",
			NULL, NULL, (LPBYTE) &dcfg->Set_Server_Values, &dwRead);

#	ifndef COOKIE_PATH
		dwRead = sizeof (dcfg->appid);
		RegQueryValueEx (hKey, "AppId",
			NULL, NULL, (LPBYTE) dcfg->appid, &dwRead);
#	endif		
		
		if (dcfg->logout_action != LOGOUT_NONE) {   //Local logout cannot be authenticated. Redirect could, but isn't
			dcfg->AuthType = AUTH_NONE;
		}
		
	}
    
	RegCloseKey (hKey); 
	
}

void Get_Effective_Values(HTTP_FILTER_CONTEXT* pFC,
						  HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo,
						  char* ptr)
{
	char key[1024+MAX_PATH], szBuff[1025];
	char *pachUrl;
	pubcookie_dir_rec* dcfg;
	DWORD dwBufferSize = 1024;
	char strbuff[MAX_REG_BUFF];

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	// Initialize default values  
	// These can be overriden in /default

	dcfg->inact_exp = PBC_DEFAULT_INACT_EXPIRE;
	dcfg->hard_exp  = PBC_DEFAULT_HARD_EXPIRE;

	strcpy(dcfg->pszUser,"");
	strcpy(dcfg->pszPassword,"");
	strcpy(dcfg->force_reauth,PBC_NO_FORCE_REAUTH);
	dcfg->session_reauth = 0;
	dcfg->AuthType = AUTH_NONE;
	dcfg->logout_action = LOGOUT_NONE;
	strcpy(dcfg->Enterprise_Domain,(PBC_ENTRPRS_DOMAIN));
	strcpy(dcfg->Login_URI, (PBC_LOGIN_URI));
	strcpy(dcfg->Error_Page,"");
	dcfg->Set_Server_Values = false;
	dcfg->legacy = false;
	
    // Then Look in default key
	
	strcpy (key, (PBC_WEB_VAR_LOCATION));
	strcat (key,"\\");
	strcat (key, PBC_DEFAULT_KEY);

	Read_Reg_Values (key, dcfg);


	// Then first node (current appid)

	strcpy (key, PBC_WEB_VAR_LOCATION);
	strcat (key,"\\");
	strcat (key, dcfg->appid);

	Read_Reg_Values (key, dcfg);

	// Then any app/subdirectory/file settings

	while ( ptr ) { // while we still have a '/' left to deal with

		pachUrl = ptr + 1;
		ptr = strchr(pachUrl,'/');

		if (ptr) {
			strncpy(szBuff, pachUrl, ptr-pachUrl);
			szBuff[ptr-pachUrl] = NULL;
		}
		else {
			strcpy(szBuff,pachUrl);
		}

		if (!strlen(szBuff)) {
			break;
		}

		// Legacy hack for special tokens PBC_PUBLIC, UWNETID and SECURID

		if ((PBC_LEGACY_DIR_NAMES)) {
			if ( stricmp((const char *)szBuff, (PBC_NETID_NAME)) == 0 ) {
				dcfg->AuthType = AUTH_NETID;
				dcfg->legacy = true;
				filterlog(dcfg, LOG_INFO,"  dir type       : %s\n",szBuff);
			}
			else if ( stricmp((const char *)szBuff, (PBC_SECURID_NAME)) == 0 ) {
				dcfg->AuthType = AUTH_SECURID;
				dcfg->legacy = true;
				filterlog(dcfg, LOG_INFO,"  dir type       : %s\n",szBuff);
			}
			else if ( stricmp((const char *)szBuff, (PBC_PUBLIC_NAME)) == 0 ) {
				dcfg->AuthType = AUTH_NONE;
				dcfg->Set_Server_Values = true;
				dcfg->legacy = true;
				filterlog(dcfg, LOG_INFO,"  dir type       : %s\n",szBuff);
			}
		}

		strcat (key, "\\");
		strcat (key, szBuff);

		Read_Reg_Values (key, dcfg);

	}

#ifndef COOKIE_PATH
	// Convert appid to lower case
	strlwr(dcfg->appid);
#endif

	{ 
		char buff[4096];

		_snprintf(buff,4096,
			"Get_Effective_Values\n" 
			"  Values for: %s\n" 
			"    AppId            : %s\n" 
			"    NtUserId         : %s\n" 
			"    Password?        : %d\n" 
			"    Inact_Exp        : %d\n" 
			"    Hard_Exp         : %d\n" 
			"    Force_Reauth     : %s\n" 
			"    Session_Reauth   : %1d\n" 
			"    Logout_Action    : %1d\n" 
			"    AuthType         : %c\n" 
			"    Default_Url      : %s\n" 
			"    Timeout_Url      : %s\n" 
			"    Login_URI        : %s\n" 
			"    Enterprise_Domain: %s\n" 
			"    Error_Page       : %s\n" 
			"    Set_Server_Values: %d\n",
			key,
			dcfg->appid,
			dcfg->pszUser,
			(strlen(dcfg->pszPassword) > 0),
			dcfg->inact_exp,
			dcfg->hard_exp,
			dcfg->force_reauth,
			dcfg->session_reauth,
			dcfg->logout_action,
			dcfg->AuthType,
			dcfg->default_url,
			dcfg->timeout_url,
			dcfg->Login_URI,
			dcfg->Enterprise_Domain,
			dcfg->Error_Page,
			dcfg->Set_Server_Values);
		
	filterlog(dcfg, LOG_INFO,buff);
	}
	sprintf(dcfg->s_cookiename,"%s_%s",PBC_S_COOKIENAME,dcfg->appid);

} 


void Add_Header_Values(HTTP_FILTER_CONTEXT* pFC,
					   HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char temp[16];
	pubcookie_dir_rec* dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	// Set Pubcookie Appid, User and Creds level

	pHeaderInfo->AddHeader(pFC,PBC_Header_Server,dcfg->server_hostname);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Appid,dcfg->appid);

//	pHeaderInfo->SetHeader(pFC,"REMOTE_USER",dcfg->user);
// Don't know how to override server variables so use our own

	pHeaderInfo->AddHeader(pFC,PBC_Header_User,dcfg->user);

	sprintf(temp,"%c",dcfg->AuthType);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Creds,temp);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Version,Pubcookie_Version);

}  /* Add_Header_Values */


int Pubcookie_User (HTTP_FILTER_CONTEXT* pFC,
					HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{

	char *cookie;
	char *current_appid;
	pbc_cookie_data *cookie_data;
    char achUrl[1025];
	char szBuff[1025];
    DWORD cbURL=1024;
	DWORD dwBuffSize;
	char *pachUrl;
	char *ptr;
	pubcookie_dir_rec* dcfg;
	int pre_sess_from_cookie;
	char strbuff[MAX_REG_BUFF];

    dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO," Pubcookie_User\n");

    // First check to see if this directory needs protection

	// Fetch requested URL

    pHeaderInfo->GetHeader(pFC,"url",achUrl,&cbURL);

	filterlog(dcfg, LOG_INFO,"  Requested URL : %s\n",achUrl);

	// Have to parse Query_String ourselves, server hasn't scanned it yet

	ptr = strchr(achUrl,'?');
	if (ptr) {
		*ptr++;
		strncpy(szBuff, ptr, strlen(ptr));
		szBuff[strlen(ptr)] = NULL;
		strcpy(dcfg->args,szBuff);
		filterlog(dcfg, LOG_INFO,"  Query String  : %s\n",szBuff);
	}
	// Else dfcg->args[0]=NULL because of original memset

	// Normalize the URL - take out all those nasty ../ and %xx

	pFC->ServerSupportFunction(pFC,SF_REQ_NORMALIZE_URL,
								achUrl,NULL,NULL);

	filterlog(dcfg, LOG_DEBUG,"  Normalized URL: %s\n",achUrl);

	// set Uri
	strcpy(dcfg->uri,achUrl);

	// set Request Method
	dwBuffSize = sizeof(dcfg->method);
	pHeaderInfo->GetHeader(pFC,"method",dcfg->method,&dwBuffSize);

	filterlog(dcfg, LOG_INFO,"  Request Method: %s\n",dcfg->method);

	// Get Application ID from first node

	strcpy((char *)dcfg->appid,(PBC_DEFAULT_APP_NAME));
	dcfg->user[0]  = NULL;
	dcfg->AuthType    = AUTH_NONE;

	pachUrl = achUrl;

	if ( PBC_IGNORE_POLL && strlen(pachUrl) == 1 ) {
		// Don't care about "/" - Possibly Network Dispatcher Polling
		return DECLINED;
	}

    *pachUrl++;		// skip over first '/'
    ptr = strchr(pachUrl,'/');
	if ( ptr ) {
		strncpy((char *)dcfg->appid, pachUrl, ptr-pachUrl);
		dcfg->appid[(ptr-pachUrl)] = NULL;
	}
	else if (strlen(pachUrl) > 0) {   // This could set appid to a filename in the root dir
		strcpy((char *)dcfg->appid, pachUrl);
	}

	// Save Path unchanged so cookies will be returned properly
	// strcpy(dcfg->path_id,dcfg->appid);

	// Get userid, timeouts, AuthType, etc for this app.  Could change appid.
	Get_Effective_Values(pFC,pHeaderInfo,ptr);

    /* Log out if indicated */

	if (dcfg->logout_action > LOGOUT_NONE) {
#ifdef COOKIE_PATH
		if ( stricmp(dcfg->appid,(PBC_DEFAULT_APP_NAME)) == 0 )
			strcpy(szBuff,"/");
		else 
			sprintf(szBuff,"/%s",dcfg->appid);
#else
		strcpy(szBuff,"/");
#endif
		//  If we're logging out, clear the cookie.
		
		Clear_Cookie(pFC,dcfg->s_cookiename,dcfg->appsrvid,szBuff,FALSE); 
		
		if (dcfg->logout_action == LOGOUT_REDIRECT || dcfg->logout_action == LOGOUT_REDIRECT_CLEAR_LOGIN) {
			
			filterlog(dcfg, LOG_INFO,"  Logout Redirect....\n");
			
			sprintf(szBuff, "%s?%s=%d&%s=%s&%s=%s",
				dcfg->Login_URI,
				PBC_GETVAR_LOGOUT_ACTION,
				(dcfg->logout_action == LOGOUT_REDIRECT_CLEAR_LOGIN ? LOGOUT_ACTION_CLEAR_L : LOGOUT_ACTION_NOTHING),
				PBC_GETVAR_APPID,
				dcfg->appid,
				PBC_GETVAR_APPSRVID,
				dcfg->appsrvid);
			
			
			dcfg->failed = PBC_LOGOUT_REDIR;
			dcfg->handler = PBC_LOGOUT_REDIR;
			
			return (Redirect(pFC, szBuff));
			
		}
		else {
			return DECLINED;  // continue serving the logout page if we're not redirecting
		}
	}

	/* We're done if this is an unprotected page */
	if (dcfg->AuthType == AUTH_NONE) {
		if (dcfg->Set_Server_Values) {
			Add_Header_Values   (pFC,pHeaderInfo);
		}
		return DECLINED;
	}

	// Can't see cookies unless we are SSL. Redirect to https if needed.

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT_SECURE",
							szBuff, &dwBuffSize);
	if ( strcmp(szBuff,"0") == 0 ) 
	{
		dcfg->failed = PBC_BAD_PORT;
		sprintf(szBuff,"https://%s%s%s%s",dcfg->appsrvid, achUrl,(strlen(dcfg->args) ? "?" : ""), dcfg->args);
		return(Redirect(pFC,szBuff));
	}



	filterlog(dcfg, LOG_INFO,"  creds= %c\n",dcfg->AuthType);


	// Set force reauth URL to requested URL if not "NFR"
	if ( strcmp(dcfg->force_reauth,PBC_NO_FORCE_REAUTH) != 0 )
		if ( strlen(dcfg->default_url) > 0 )
			strcpy((char *)dcfg->force_reauth,dcfg->default_url);
		else
			strcpy((char *)dcfg->force_reauth,achUrl);

    // Get Granting cookie or Session cookie
	// If '<cookie name>=' then client has bogus time and cleared cookie hasn't expired

	if( !(cookie = Get_Cookie(pFC,PBC_G_COOKIENAME)) || (strcmp(cookie,"")==0) ) {
		if (cookie) pbc_free(p, cookie);
		if( !(cookie = Get_Cookie(pFC,dcfg->s_cookiename)) || (strcmp(cookie,"")==0) ) {
			filterlog(dcfg, LOG_INFO,"  Pubcookie_User: no cookies yet, must authenticate\n");
			if (cookie) pbc_free(p, cookie);
			dcfg->failed = PBC_BAD_AUTH;
			return OK;
		}
		else {

			if( ! (cookie_data = libpbc_unbundle_cookie(p, cookie, dcfg->server_hostname, false)) ) {
				filterlog(dcfg, LOG_ERR,"[Pubcookie_User] Can't unbundle Session cookie for URL %s; remote_host: %s",
					dcfg->uri, dcfg->remote_host);
				dcfg->failed = PBC_BAD_SESSION_CERT;
				pbc_free(p, cookie);
				return OK;
			}
		else {
			dcfg->cookie_data = cookie_data;
		}

		pbc_free(p, cookie);

		filterlog(dcfg, LOG_INFO,"  Session Cookie Contents:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    create_ts= %d\n    last_ts= %d\n",
			(*cookie_data).broken.user,(*cookie_data).broken.version,(*cookie_data).broken.appsrvid,
			(*cookie_data).broken.appid,(*cookie_data).broken.type,(*cookie_data).broken.creds,
			(*cookie_data).broken.create_ts,(*cookie_data).broken.last_ts);

		strcpy(dcfg->user, (char *)(*cookie_data).broken.user);

		// maintain highest level of creds
		if ( dcfg->AuthType == AUTH_NETID && (*cookie_data).broken.creds == AUTH_SECURID )
			 dcfg->AuthType = AUTH_SECURID;

		if( ! Pubcookie_Check_Exp(pFC,(*cookie_data).broken.create_ts,dcfg->hard_exp)) {
			filterlog(dcfg, LOG_INFO,"  Session cookie hard expired for user: %s create_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.create_ts,
                dcfg->hard_exp,
                (time(NULL)-(*cookie_data).broken.create_ts) );
			if ( strcmp(dcfg->force_reauth,PBC_NO_FORCE_REAUTH) != 0 &&
				 strlen(dcfg->timeout_url) > 0 )
				strcpy((char *)dcfg->force_reauth,dcfg->timeout_url);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}
		else {
			filterlog(dcfg, LOG_INFO,"  Session cookie not hard expired for user: %s create_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.create_ts,
                dcfg->hard_exp,
                (time(NULL)-(*cookie_data).broken.create_ts) );
		}

		if(dcfg->inact_exp != -1 &&
			! Pubcookie_Check_Exp(pFC,(*cookie_data).broken.last_ts,dcfg->inact_exp) ) {
			filterlog(dcfg, LOG_INFO,"  Session cookie inact expired for user: %s last_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.last_ts,
                dcfg->inact_exp,
                (time(NULL)-(*cookie_data).broken.last_ts) );
			if ( strcmp(dcfg->force_reauth,PBC_NO_FORCE_REAUTH) != 0 &&
				 strlen(dcfg->timeout_url) > 0 )
				strcpy((char *)dcfg->force_reauth,dcfg->timeout_url);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}

		} /* end if session cookie */

	}
	else {

		dcfg->has_granting = 1;

		/* the granting cookie gets blanked too early and another login */
		/* server loop is required, this just speeds up that loop */
		/*if( strncmp(cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0 ) {
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie);
			return OK;
		}*/ 		/* PBC_X_STRING doesn't seem to be used any longer */


		if( !(cookie_data = libpbc_unbundle_cookie(p, cookie, dcfg->server_hostname, true)) ) {
			filterlog(dcfg, LOG_ERR,"[Pubcookie_User] Can't unbundle Granting cookie for URL %s; remote_host: %s", 
				dcfg->uri, dcfg->remote_host);
			dcfg->failed = PBC_BAD_GRANTING_CERT;
			pbc_free(p, cookie);
			return OK;
		}

		/* check pre_session cookie */
		pre_sess_from_cookie = get_pre_s_from_cookie(pFC);
		if( (*cookie_data).broken.pre_sess_token != pre_sess_from_cookie ) {
			filterlog(dcfg, LOG_INFO,"pubcookie_user, pre session tokens mismatched, uri: %s", dcfg->uri);
			filterlog(dcfg, LOG_INFO,"pubcookie_user, pre session from G: %d PRE_S: %d, uri: %s", 
				(*cookie_data).broken.pre_sess_token, pre_sess_from_cookie, dcfg->uri);
			dcfg->failed = PBC_BAD_AUTH;
			return OK;
		}



		pbc_free(p, cookie);

		filterlog(dcfg, LOG_INFO,"  Granting Cookie Contents:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    create_ts= %d\n    last_ts= %d\n",
			(*cookie_data).broken.user  ,(*cookie_data).broken.version  ,(*cookie_data).broken.appsrvid,
			(*cookie_data).broken.appid,(*cookie_data).broken.type     ,(*cookie_data).broken.creds,
			(*cookie_data).broken.create_ts,(*cookie_data).broken.last_ts);

		strcpy(dcfg->user,(const char *)(*cookie_data).broken.user);

		// maintain highest level of creds
		if ( dcfg->AuthType == AUTH_NETID && (*cookie_data).broken.creds == AUTH_SECURID )
			 dcfg->AuthType = AUTH_SECURID;

		if( ! Pubcookie_Check_Exp(pFC,(*cookie_data).broken.create_ts, PBC_GRANTING_EXPIRE) ) {
			filterlog(dcfg, LOG_INFO,"[Pubcookie_User] Granting cookie expired for user: %s  elapsed: %d limit: %d; remote_host: %s", 
				(*cookie_data).broken.user,(time(NULL)-(*cookie_data).broken.create_ts), PBC_GRANTING_EXPIRE, dcfg->remote_host);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}

	} /* end if granting cookie */

	/* check appid */
	current_appid = dcfg->appid;
	if( _strnicmp((const char *)current_appid, (const char *)(*cookie_data).broken.appid, 
					sizeof((*cookie_data).broken.appid)-1) != 0 ) {
	//	filterlog(dcfg, LOG_ERR,"[Pubcookie_User] Wrong appid; current: %s cookie: %s; remote_host: %s", 
	//		current_appid, (*cookie_data).broken.appid, dcfg->remote_host);
		dcfg->failed = PBC_BAD_AUTH;   // PBC_BAD_APPID;  // Left over from failed application
		pbc_free(p, cookie_data);
		return OK;
	}

	/* make sure this cookie is for this server */
	/* Use server_hostname instead of appsrvid so we only need one c_key per server */
	if( _strnicmp((const char *)dcfg->server_hostname, (const char *)(*cookie_data).broken.appsrvid, 
					sizeof((*cookie_data).broken.appsrvid)-1) != 0 ) {
		filterlog(dcfg, LOG_WARN,"[Pubcookie_User] Wrong app server id; current: %s cookie: %s; remote_host: %s", 
				dcfg->server_hostname, (*cookie_data).broken.appsrvid, dcfg->remote_host);
		dcfg->failed = PBC_BAD_AUTH;  // PBC_BAD_SERVERID;
		pbc_free(p, cookie_data);
		return OK;  
	}

	if( !Pubcookie_Check_Version(pFC,(*cookie_data).broken.version, 
			(unsigned char *)PBC_VERSION)){
		filterlog(dcfg, LOG_ERR,"[Pubcookie_User] Wrong version id; module: %d cookie: %d", 
				PBC_VERSION, (*cookie_data).broken.version);
		dcfg->failed = PBC_BAD_VERSION;
		pbc_free(p, cookie_data);
		return OK;
	}

	if(dcfg->AuthType == AUTH_NETID ) {
		if( (*cookie_data).broken.creds != AUTH_NETID &&
			(*cookie_data).broken.creds != AUTH_SECURID    ) {
			filterlog(dcfg, LOG_ERR,"[Pubcookie_User] Wrong creds directory; %c cookie: %c", 
				AUTH_NETID, (*cookie_data).broken.creds);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		} else {
			dcfg->AuthType = (*cookie_data).broken.creds;   // Use Creds from Cookie
			}
	}
	else
	if(dcfg->AuthType == AUTH_SECURID ) {
		if( (*cookie_data).broken.creds != AUTH_SECURID ) {
			filterlog(dcfg, LOG_ERR,"  Pubcookie_User: Wrong creds directory; %c cookie: %c", 
				AUTH_SECURID, (*cookie_data).broken.creds);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}
	}

//	pbc_free(cookie_data);  /*Need this later to reset timestamp*/

	return OK;

}  /* Pubcookie_User */


int Pubcookie_Auth (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO," Pubcookie_Auth\n");

	if( !Is_Pubcookie_Auth(dcfg) ) 
		return DECLINED;

	if(dcfg->failed)  /* Pubcookie_User has failed so pass to typer */
		return OK;

	return DECLINED;

}  /* Pubcookie_Auth */


int Pubcookie_Typer (HTTP_FILTER_CONTEXT* pFC,
					 HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo) 
{
	unsigned char	*cookie;
	int first_time_in_session = 0;
	pubcookie_dir_rec* dcfg;
	char session_cookie_name[MAX_PATH];

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_DEBUG," Pubcookie_Typer\n");

	if( dcfg->logout_action ) 
		return OK;  //if we got here while logging out, we're redirecting
	if( !Is_Pubcookie_Auth(dcfg) ) 
		return DECLINED;  //if we got here without auth, something must have changed midstream

	filterlog(dcfg, LOG_INFO," Pubcookie_Typer\n Has_Granting= %d, Failed= %d\n",dcfg->has_granting,dcfg->failed);

	if (dcfg->has_granting ) {

		/* clear granting and presession cookies */
		Clear_Cookie(pFC,PBC_G_COOKIENAME,dcfg->Enterprise_Domain,"/",TRUE);
		Clear_Cookie(pFC,PBC_PRE_S_COOKIENAME,dcfg->appsrvid,"/",TRUE);

		first_time_in_session = 1;
		dcfg->has_granting = 0;
	}

	if (!dcfg->failed) {
	/* if the inactivity timeout is turned off don't send a session cookie 
	everytime, but be sure to send a session cookie if it's the first time
	in the app */
		if (dcfg->inact_exp > 0 || first_time_in_session) {
			
			if( !first_time_in_session ) {
				cookie = libpbc_update_lastts(p, dcfg->cookie_data, dcfg->server_hostname, 0);
				filterlog(dcfg, LOG_INFO,"  Setting session cookie last timestamp to: %ld\n",dcfg->cookie_data->broken.last_ts);
			}
			else {
				cookie = libpbc_get_cookie(p,
					(unsigned char *)dcfg->user, 
					PBC_COOKIE_TYPE_S,
					dcfg->AuthType,
					23,
					(unsigned char *)dcfg->server_hostname, 
					(unsigned char *)dcfg->appid,
					dcfg->server_hostname,
					0);

				filterlog(dcfg, LOG_INFO,"  Created new session cookie.\n");
			}



#ifdef COOKIE_PATH
			if ( stricmp(dcfg->appid,(PBC_DEFAULT_APP_NAME)) == 0 )
				sprintf(new_cookie, "Set-Cookie: %s_%s=%s; domain=%s; path=/; secure\r\n", 
				PBC_S_COOKIENAME, dcfg->appid,
				cookie, 
				dcfg->appsrvid);
			else 
				sprintf(new_cookie, "Set-Cookie: %s_%s=%s; domain=%s; path=/%s; secure\r\n", 
				PBC_S_COOKIENAME, dcfg->appid,
				cookie, 
				dcfg->appsrvid,
				dcfg->appid);

			pFC->AddResponseHeaders(pFC,new_cookie,0);

#else
			snprintf(session_cookie_name,MAX_PATH,"%s_%s",PBC_S_COOKIENAME,dcfg->appid);
			Add_Cookie(pFC,session_cookie_name,cookie,dcfg->appsrvid);
			
	
#endif
			pbc_free(p, cookie);
			pbc_free(p, dcfg->cookie_data);
			
		
		}
		// Have a good session cookie at this point
		// Now set effective UserId ,UWNetID and Creds values for ASP pages
		
		Add_Header_Values(pFC,pHeaderInfo);

		return DECLINED;

	} else if (dcfg->failed == PBC_BAD_AUTH) {
		dcfg->handler = PBC_BAD_AUTH;
		return OK;
	} else if (dcfg->failed == PBC_BAD_USER) {
		dcfg->handler = PBC_BAD_USER;
		return OK;
	} else if (dcfg->failed == PBC_FORCE_REAUTH) {
		dcfg->handler = PBC_FORCE_REAUTH;
		return OK;
	} else if (dcfg->failed == PBC_BAD_GRANTING_CERT) {
		dcfg->handler = PBC_BAD_GRANTING_CERT;
		return OK;
	} else if (dcfg->failed == PBC_BAD_SESSION_CERT) {
		dcfg->handler = PBC_BAD_SESSION_CERT;
		return OK;
	} else if (dcfg->failed == PBC_BAD_VERSION) {
		dcfg->handler = PBC_BAD_VERSION;
		return OK;
	} else if (dcfg->failed == PBC_BAD_APPID) {
		dcfg->handler = PBC_BAD_APPID;
		return OK;
	} else if (dcfg->failed == PBC_BAD_SERVERID) {
		dcfg->handler = PBC_BAD_SERVERID;
		return OK;
	} else if (dcfg->failed == PBC_BAD_PORT) {
		dcfg->handler = PBC_BAD_PORT;
		return OK;
	} else {
		return DECLINED;

	}

}  /* Pubcookie_Typer */



BOOL WINAPI GetFilterVersion (HTTP_FILTER_VERSION* pVer)
{

	// The version of the web server this is running on
	syslog(LOG_INFO, "\nPBC_GetFilterVersion: Web Server is version is %d.%d\n",
				HIWORD( pVer->dwServerFilterVersion ),
				LOWORD( pVer->dwServerFilterVersion ) );

	// Filter version we expect.
	pVer->dwFilterVersion =  HTTP_FILTER_REVISION; // MAKELONG( 0, 4 ); Version 4.0

	// The description
	strcpy( pVer->lpszFilterDesc, Pubcookie_Version );
	
	syslog(LOG_INFO,"[GetFilterVersion] %s",Pubcookie_Version);

	pVer->dwFlags = Notify_Flags;

	return TRUE;

}  /* GetFilterVersion */


DWORD OnReadRawData (HTTP_FILTER_CONTEXT *pFC,
                     HTTP_FILTER_RAW_DATA *pRawDataInfo)
{
	pubcookie_dir_rec* dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(dcfg, LOG_INFO,
		"\nPBC_OnReadRawData\n"
		"  Revision: x%x\n"
		"  Secure  : x%x\n"
		,pFC->Revision,pFC->fIsSecurePort);
	
	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnReadRawData */

DWORD OnPreprocHeaders (HTTP_FILTER_CONTEXT* pFC,
                        HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char szBuff[1024];
	char achUrl[1024];
	char LogBuff[LOGBUFFSIZE]="";
//	char *ptr;
	DWORD dwBuffSize=1024;
	DWORD return_rslt;
//	unsigned long net_addr;
//	hostent *hp;
	pubcookie_dir_rec* dcfg;
	time_t ltime;
	char SystemRootBuff[MAX_PATH+1];

	// IBM Network Dispatcher probes web sites with a URL of "/" and command of HEAD
	// bail quickly if this is the case

	achUrl[0]= NULL; dwBuffSize=1024;
	pHeaderInfo->GetHeader(pFC, "url",
							achUrl, &dwBuffSize);

	if ( PBC_IGNORE_POLL && strcmp(achUrl,"/") == 0 ) {
		pFC->ServerSupportFunction(pFC,SF_REQ_DISABLE_NOTIFICATIONS,
								NULL,Notify_Flags,NULL);
		return SF_STATUS_REQ_NEXT_NOTIFICATION;
	}

	// pFC->pFilterContext = pbc_malloc(p, sizeof(pubcookie_dir_rec));
	pFC->pFilterContext = pFC->AllocMem(pFC,sizeof(pubcookie_dir_rec),0);

	if (!pFC->pFilterContext) {
		syslog(LOG_ERR,"[PBC_OnPreprocHeaders] Error allocating memory");
		return SF_STATUS_REQ_ERROR;
	}
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;
	
	memset(dcfg,0,sizeof(pubcookie_dir_rec));

	time(&ltime);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "INSTANCE_ID",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Instance ID    : %s\n",szBuff);
	strncpy(dcfg->instance_id, szBuff, 8);

	//Check for logging sources and create if needed

	_snprintf (szBuff,1024,"Pubcookie-%s",dcfg->instance_id);
	if (!logsource_exists(szBuff)) {
		create_source(szBuff);
	}
	if (!logsource_exists("PubCookie")) {
		create_source("PubCookie");
	}

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable (pFC,
      "SERVER_NAME",szBuff,&dwBuffSize);
	AddToLog(LogBuff,"  Server Name    : %s\n",szBuff);
	strncpy((char *)dcfg->server_hostname, szBuff, PBC_APPSRV_ID_LEN);
	strncpy(dcfg->appsrvid, szBuff, PBC_APPSRV_ID_LEN);   // Use SERVER_NAME for appsrvid

	filterlog(dcfg, LOG_INFO,"\n %s \n PBC_OnPreprocHeaders\n",ctime(&ltime));
	filterlog(dcfg, LOG_INFO,"\n Using crypt key: %s\\%s",PBC_KEY_DIR,dcfg->server_hostname);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "REMOTE_HOST",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Remote_Host    : %s\n",szBuff);
	strcpy(dcfg->remote_host,szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "HTTP_REFERER",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Referer        : %s\n",szBuff);

	AddToLog(LogBuff,"  Requested URL  : %s\n",achUrl);
	
	szBuff[0]= NULL; dwBuffSize=1024;
	pHeaderInfo->GetHeader(pFC, "method",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Request_Method : %s\n",szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pHeaderInfo->GetHeader(pFC, "Content-Length:",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Content_Length : %s\n",szBuff);

	AddToLog(LogBuff,"  HttpStatus     : %d\n",pHeaderInfo->HttpStatus);
 
	szBuff[0]= NULL; dwBuffSize=1024; 
	pFC->GetServerVariable(pFC, "URL",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Server URL     : %s\n",szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT_SECURE",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Server Secure  : %s\n",szBuff);
   
	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"LOCAL_ADDR",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Server LOCAL_ADDR : %s\n",szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Server SERVER_PORT: %s\n",szBuff);
	strcpy(dcfg->appsrv_port,szBuff);
	// Force port 80 or 443(ssl) to null
	if ( strcmp(dcfg->appsrv_port, "80") == 0 ||
	 	 strcmp(dcfg->appsrv_port,"443") == 0    )
		strcpy(dcfg->appsrv_port,"");

//	szBuff[0]= NULL; dwBuffSize=1024;
//	pFC->GetServerVariable(pFC,"QUERY_STRING",
//							szBuff, &dwBuffSize);
//	AddToLog(LogBuff,"  Server QUERY_STRING: %s\n",szBuff);

//	szBuff[0]= NULL; dwBuffSize=1024;
//	pHeaderInfo->GetHeader(pFC,"QUERY_STRING:",
//							szBuff, &dwBuffSize);
//	AddToLog(LogBuff,"  Header QUERY_STRING: %s\n",szBuff);
//	strcpy(dcfg->args,szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"HTTP_HOST",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Server HTTP_HOST  : %s\n",szBuff);

	return_rslt = SF_STATUS_REQ_NEXT_NOTIFICATION;
	dcfg->pszUser[0] = NULL;    // For OnAuth

	filterlog(dcfg, LOG_INFO, LogBuff);

   // Begin Pubcookie logic

	if ( Pubcookie_User(pFC,pHeaderInfo) == OK ) 
//		if ( Pubcookie_Auth(pFC) == OK )
			if ( Pubcookie_Typer(pFC,pHeaderInfo) == OK )
				switch (dcfg->handler)
				{
				case PBC_BAD_AUTH:
					Auth_Failed(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_FORCE_REAUTH:
					Auth_Failed(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_USER:
					Bad_User(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_GRANTING_CERT:
					Bad_User(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_SESSION_CERT:
					Bad_User(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_VERSION:
					Bad_User(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_APPID:
					// Bad_User(pFC);
					Auth_Failed(pFC);	  // Lets try again
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_SERVERID:
					Bad_User(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_BAD_PORT:      // Redirected to https
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				case PBC_LOGOUT_REDIR:   // Redirected to logout server
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;
				default:
					filterlog(dcfg, LOG_ERR,"[PBC_OnPreprocHeaders] Unexpected dcfg->handler value = %d",
						dcfg->handler);
					return_rslt = SF_STATUS_REQ_ERROR;
					break;
				}
			else
				Hide_Cookies(pFC,pHeaderInfo);
//		else
//			Hide_Cookies(pFC,pHeaderInfo);
	else
		Hide_Cookies(pFC,pHeaderInfo);

	filterlog(dcfg, LOG_DEBUG," OnPreprocHeaders returned x%X\n",return_rslt);
	
	return return_rslt;

} /* OnPreprocHeaders */


DWORD OnUrlMap (HTTP_FILTER_CONTEXT* pFC, 
			    HTTP_FILTER_URL_MAP* pUrlMapInfo)
{
	char LogBuff[LOGBUFFSIZE]="";
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		AddToLog(LogBuff,"PBC_OnUrlMap (%s)\n",dcfg->remote_host);
	}else {
		AddToLog(LogBuff,"PBC_OnUrlMap\n");
	}

	AddToLog(LogBuff,"  PhysicalPath: %s\n",pUrlMapInfo->pszPhysicalPath);

	filterlog(dcfg, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

} /* OnUrlMap */


DWORD OnAuthentication (HTTP_FILTER_CONTEXT* pFC,
                        HTTP_FILTER_AUTHENT* pAuthInfo)
{
	pubcookie_dir_rec* dcfg;
	char LogBuff[LOGBUFFSIZE]="";
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		AddToLog(LogBuff,"PBC_OnAuthentication (%s)\n",dcfg->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnAuthentication\n");
	}

	AddToLog(LogBuff,"  Old UserName: %s\n",pAuthInfo->pszUser);
//	AddToLog(LogBuff,"  Old Password: %s\n",pAuthInfo->pszPassword);

	if ( dcfg )
	if ( strlen(dcfg->pszUser) > 0 && dcfg->legacy) {
		// Give the mapped user/password back to the server
		strcpy(pAuthInfo->pszUser    , dcfg->pszUser);
		strcpy(pAuthInfo->pszPassword, dcfg->pszPassword);

		AddToLog(LogBuff,"  New UserName : %s\n",pAuthInfo->pszUser);
		AddToLog(LogBuff,"  New PW length: %d\n",strlen(pAuthInfo->pszPassword));
	}
	filterlog(dcfg, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnAuthentication */


DWORD OnAccessDenied (HTTP_FILTER_CONTEXT* pFC, 
					  HTTP_FILTER_ACCESS_DENIED* pDenyInfo)
{
	pubcookie_dir_rec* dcfg;
	char LogBuff[LOGBUFFSIZE]="";

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		AddToLog(LogBuff,"PBC_OnAccessDenied (%s)\n",dcfg->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnAccessDenied\n");
	}

	AddToLog(LogBuff,"  URL   : %s\n",pDenyInfo->pszURL);
	AddToLog(LogBuff,"  PATH  : %s\n",pDenyInfo->pszPhysicalPath);
	AddToLog(LogBuff,"  Reason: x%x\n",pDenyInfo->dwReason);

	filterlog(dcfg, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnAccessDenied */


DWORD OnSendResponse (HTTP_FILTER_CONTEXT* pFC,
                      HTTP_FILTER_SEND_RESPONSE* pResponseInfo)
{
	pubcookie_dir_rec* dcfg;
	char LogBuff[LOGBUFFSIZE]="";

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		AddToLog(LogBuff,"PBC_OnSendResponse (%s)\n",dcfg->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnSendResponse\n");
	}

	AddToLog(LogBuff,"  HttpStatus: %d\n",pResponseInfo->HttpStatus);

	filterlog(dcfg, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnSendResponse */ 


DWORD OnSendRawData (HTTP_FILTER_CONTEXT* pFC,
                     HTTP_FILTER_RAW_DATA* pRawDataInfo)
{
	pubcookie_dir_rec* dcfg;
	char LogBuff[LOGBUFFSIZE]="";

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		AddToLog(LogBuff,"PBC_OnSendRawData (%s)\n",dcfg->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnSendRawData\n");
	}

	AddToLog(LogBuff,"  Sending(%d): \n%.*s\n",
		pRawDataInfo->cbInData,pRawDataInfo->cbInData,pRawDataInfo->pvInData);

	filterlog(dcfg, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnSendRawData */


DWORD OnEndOfRequest (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		filterlog(dcfg, LOG_INFO,"PBC_OnEndOfRequest (%s)\n",dcfg->remote_host);
	} else {
		filterlog(dcfg, LOG_INFO,"PBC_OnEndOfRequest\n");
	}
			
	// OnEndOfNetSession is not called consistantly for each request,
	// free here instead.
	// Assumes we don't need this structure in OnLog below
	// **Need to use AllocMem instead** we can't be sure we don't need it in OnLog.
	
	//pbc_free(p, pFC->pFilterContext);

	//pFC->pFilterContext = NULL;   // Force to Null so we don't try to free twice

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnEndOfRequest */

VOID ReplaceToken(const char *token,const char *data, char *psztarget, int targetsize)
{
	char *l1;
	char *szbuff=NULL;

	while (l1=strstr(psztarget,token)) {
		szbuff = (char *)realloc(szbuff,sizeof(char) * (strlen(psztarget) + strlen(data) - strlen(token) + 1));
		szbuff[0] = 0;
		strncat(szbuff,psztarget,l1-psztarget);
		strcat(szbuff,data);
		strcat(szbuff,l1+strlen(token));
		strncpy(psztarget,szbuff,targetsize);
	}

	free(szbuff);

}

DWORD OnLog (HTTP_FILTER_CONTEXT* pFC, 
		  	 HTTP_FILTER_LOG* pLogInfo)
{
	char szBuff[1024];
	char LogBuff[LOGBUFFSIZE]="";
	DWORD dwBuffSize,dwReserved=NULL;
	pubcookie_dir_rec* dcfg;
	char *pszNewClient;
	char strbuff[MAX_REG_BUFF];

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	AddToLog(LogBuff,"PBC_OnLog\n");

	szBuff[0]= NULL; dwBuffSize=1024;

	pFC->GetServerVariable(pFC, "INSTANCE_ID",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Instance ID   : %s\n",szBuff);

	if ( dcfg ) {
		if (strlen(dcfg->user) > 0) {
			dwBuffSize=1024;
			pszNewClient = (char *)pFC->AllocMem(pFC,dwBuffSize,0);
			strncpy(pszNewClient,(PBC_CLIENT_LOG_FMT), dwBuffSize);
			ReplaceToken("%w",pLogInfo->pszClientUserName,pszNewClient, dwBuffSize);
			ReplaceToken("%p",dcfg->user, pszNewClient, dwBuffSize);
			AddToLog(LogBuff,"  Modified user : %s\n",pszNewClient);
			pLogInfo->pszClientUserName = pszNewClient;
		}
	}
	AddToLog(LogBuff,"  ClientHostName: %s\n",pLogInfo->pszClientHostName);
	AddToLog(LogBuff,"  ClientUserName: %s\n",pLogInfo->pszClientUserName);
	AddToLog(LogBuff,"  ServerName    : %s\n",pLogInfo->pszServerName);
	AddToLog(LogBuff,"  Operation     : %s\n",pLogInfo->pszOperation);
	AddToLog(LogBuff,"  Target        : %s\n",pLogInfo->pszTarget);
	AddToLog(LogBuff,"  Parameters    : %s\n",pLogInfo->pszParameters);
	AddToLog(LogBuff,"  HttpStatus    : %d\n",pLogInfo->dwHttpStatus);
	AddToLog(LogBuff,"  Win32Status   : x%x\n",pLogInfo->dwWin32Status);
	AddToLog(LogBuff,"  BytesSent     : %d\n",pLogInfo->dwBytesSent);
	AddToLog(LogBuff,"  BytesReceived : %d\n",pLogInfo->dwBytesRecvd);
	AddToLog(LogBuff,"  ProcTime      : %d\n",pLogInfo->msTimeForProcessing);

	filterlog(dcfg, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnLog */


DWORD OnEndOfNetSession (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		filterlog(dcfg, LOG_INFO,"PBC_OnEndOfNetSession (%s)\n",dcfg->remote_host);
	} else {
		filterlog(dcfg, LOG_INFO,"PBC_OnEndOfNetSession\n");
	}
			
	// Free pFilterContext here if allocated via malloc
	// However this routine is not to be called consistantly due to keep alives
	// Use EndOfRequest instead

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

//	return SF_STATUS_REQ_FINISHED;    ??? not sure if this is necessary ???

}  /* OnEndOfNetSession */


DWORD WINAPI HttpFilterProc (HTTP_FILTER_CONTEXT* pFC,
                             DWORD NotificationType, VOID* pvData)
{
	DWORD dwRet;

	// Send this notification to the right function
	switch ( NotificationType )
	{
	case SF_NOTIFY_READ_RAW_DATA:
		dwRet = OnReadRawData( pFC, (PHTTP_FILTER_RAW_DATA) pvData );
		break;
	case SF_NOTIFY_PREPROC_HEADERS:
		dwRet = OnPreprocHeaders( pFC, (PHTTP_FILTER_PREPROC_HEADERS) pvData );
		break;
	case SF_NOTIFY_URL_MAP:
		dwRet = OnUrlMap( pFC, (PHTTP_FILTER_URL_MAP) pvData );
		break;
	case SF_NOTIFY_AUTHENTICATION:
		dwRet = OnAuthentication( pFC, (PHTTP_FILTER_AUTHENT) pvData );
		break;
	case SF_NOTIFY_ACCESS_DENIED:
		dwRet = OnAccessDenied( pFC, (PHTTP_FILTER_ACCESS_DENIED) pvData );
		break;
	case SF_NOTIFY_SEND_RESPONSE:
		dwRet = OnSendResponse( pFC, (PHTTP_FILTER_SEND_RESPONSE) pvData );
		break;
	case SF_NOTIFY_SEND_RAW_DATA:
		dwRet = OnSendRawData( pFC, (PHTTP_FILTER_RAW_DATA) pvData );
		break;
	case SF_NOTIFY_END_OF_REQUEST:
		dwRet = OnEndOfRequest( pFC );
		break;
	case SF_NOTIFY_LOG:
		dwRet = OnLog( pFC, (PHTTP_FILTER_LOG) pvData );
		break;
	case SF_NOTIFY_END_OF_NET_SESSION:
		dwRet = OnEndOfNetSession( pFC );
		break;
	default:
		syslog(LOG_ERR,"[PBC_HttpFilterProc] Unknown notification type, %d",
					NotificationType);
		dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;
		break;
	}

	return dwRet;

}  /* HttpFilterProc */


BOOL WINAPI TerminateFilter (DWORD dwFlags) 
{
	/* Called When Filter is Terminated */

	syslog(LOG_INFO, "\nPBC_TerminateFilter Called \n");

	WSACleanup();

	return TRUE;

}  /* TerminateFilter */

BOOL
WINAPI
DllMain(
     IN HINSTANCE hinstDll,
     IN DWORD     fdwReason,
     IN LPVOID    lpvContext OPTIONAL
     )
/*++

 Routine Description:

   This function DllMain() is the main initialization function for
    this DLL. It initializes local variables and prepares it to be invoked
    subsequently.

 Arguments:

   hinstDll          Instance Handle of the DLL
   fdwReason         Reason why NT called this DLL
   lpvReserved       Reserved parameter for future use.

 Return Value:

    Returns TRUE is successful; otherwise FALSE is returned.
--*/
{
    BOOL fReturn = TRUE;
    switch ( fdwReason )
    {
    case DLL_PROCESS_ATTACH:
		{
			// Initialize Pubcookie Stuff - and Set Debut Trace Flags
			fReturn = Pubcookie_Init ();
		
			if ( !fReturn )
				syslog(LOG_ERR, "\n*** Pubcookie_Init Failed !\n\n");
			
			//
			//  We don't care about thread attach/detach notifications
			//
			
			DisableThreadLibraryCalls( hinstDll );
			
			break;
		} /* case DLL_PROCEDD_ATTACH */
		
    case DLL_THREAD_ATTACH:
		{
			syslog(LOG_INFO, "PBC_DllMain: DLL_THREAD_ATTACH\n");
			
			break;
		} /* case DLL_THREAD_ATTACH */
		
    case DLL_THREAD_DETACH:
        {
			syslog(LOG_INFO, "PBC_DllMain: DLL_THREAD_DETACH\n");
			
			break;
        } /* case DLL_THREAD_DETACH */
		
    case DLL_PROCESS_DETACH:
        {
			syslog(LOG_INFO, "PBC_DllMain: DLL_PROCESS_DETACH\n");
			
			break;
        } /* case DLL_PROCESS_DETACH */
		
    default:
		{
			syslog(LOG_INFO, "PBC_DllMain: Unexpected Reason= %d\n",fdwReason);
			
			break;
		}
    }   /* switch */
	
	syslog(LOG_INFO, "PBC_DllMain: Returning %d\n",fReturn); 
	
    return ( fReturn);

}  /* DllMain() */


