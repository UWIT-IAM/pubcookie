// ========================================================================
// Copyright 2005 University of Washington
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ========================================================================
//

//
//  $Id: PubCookieFilter.cpp,v 1.46 2005-03-24 19:29:13 suh Exp $
//

//#define COOKIE_PATH

#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <direct.h>       // For mkdir
#include <time.h>
#include <process.h>
#include <httpfilt.h>
#include <httpext.h>

typedef void pool;

extern "C" 
{
#include <pem.h>
#include "pubcookie.h"
#include "pbc_config.h"
#include "libpubcookie.h"
#include "PubCookieFilter.h"
#include "pbc_version.h"
#include "pbc_myconfig.h"
#include "pbc_configure.h"
#include "debug.h"
#include "strlcpy.h"
//#include "strsafe.h"

}

#include "html.h"
#include "keys.h"

#define HDRSIZE 56
#define MAX_BUFFER 4096

/* a place to hold all of the certificates and keys */
struct security_context_s {
   /* our private session keypair */
   EVP_PKEY *sess_key;
   X509 *sess_cert;
   EVP_PKEY *sess_pub;

   /* the granting key & certificate */
   EVP_PKEY *g_key;
   X509 *g_cert;
   EVP_PKEY *g_pub;

   /* my name */
   char *myname;

   /* the crypt_key */
   unsigned char cryptkey[PBC_DES_KEY_BUF];
};

security_context *default_context;  //Read-only after init

VOID filterlog(pubcookie_dir_rec *p, int loglevel, const char *format, ...) {
	char source[HDRSIZE];

	va_list   args;

    va_start(args, format);
	if (p) {  
		_snprintf(source,HDRSIZE,"Pubcookie-%s",p->instance_id);
	}
	else
	{
		_snprintf(source,HDRSIZE,"Pubcookie");
	}
    filter_log_activity (p, source, loglevel, format, args );

    va_end(args);
}

bool logsource_exists(pubcookie_dir_rec *p, const char *source) {

	HKEY hKey;
	UCHAR *DataBuff;
	DWORD dsize;
	DWORD retval;
	
	if (!(DataBuff = (UCHAR *)malloc(MAX_REG_BUFF))) {
		syslog(LOG_ERR,"Malloc failed in logsource_exists");
		return FALSE;
	}
	
	//First, check to see if key exists
	dsize = MAX_REG_BUFF;
	_snprintf(p->strbuff,MAX_REG_BUFF,"System\\CurrentControlSet\\Services\\Eventlog\\Application\\%s",source);
	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		p->strbuff,0,KEY_READ,&hKey) != ERROR_SUCCESS) {
		return FALSE;
	}
	
	//Then, make sure the Event Message File is the current one
		
	if (retval = RegQueryValueEx(hKey, "EventMessageFile", NULL, NULL, DataBuff, &dsize)) {
		retval = strncmp((char *)DataBuff, AddSystemRoot(p, "\\inetsrv\\pubcookie\\pbc_messages.dll"), MAX_PATH);
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

VOID create_source(pubcookie_dir_rec *p, const char *source) {
	char keybuff[MAX_REG_BUFF];
	HKEY hKey;
	UCHAR *dataBuff;
	int dsize;
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

	SetRegString(hKey,"EventMessageFile", AddSystemRoot(p, "\\inetsrv\\pubcookie\\pbc_messages.dll"));
	SetRegDWORD(hKey,"TypesSupported",7);

	free(dataBuff);

	RegCloseKey(hKey);


}

/**
 * get a random int used to bind the granting cookie and pre-session
 * @returns random int or -1 for error
 * but, what do we do about that error?
 */
int get_pre_s_token(HTTP_FILTER_CONTEXT* pFC) {
    int i;
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;


    if( (i = libpbc_random_int(p)) == -1 ) {
        filterlog(p, LOG_ERR,	"get_pre_s_token: OpenSSL error");
    }

		filterlog(p, LOG_INFO, "get_pre_s_token: token is %d\n", i);
    return(i);

}


int get_pre_s_from_cookie(HTTP_FILTER_CONTEXT* pFC)
{
    pubcookie_dir_rec   *p;
    pbc_cookie_data     *cookie_data = NULL;
    char 		*cookie = NULL;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

    if( (cookie = Get_Cookie(pFC, PBC_PRE_S_COOKIENAME)) == NULL )

        filterlog(p, LOG_ERR,	"get_pre_s_from_cookie: no pre_s cookie, uri: %s\n", p->uri);
    else
		cookie_data = libpbc_unbundle_cookie(p, p->sectext, cookie, p->server_hostname, false);

    if( cookie_data == NULL ) {
        filterlog(p, LOG_ERR, "get_pre_s_from_cookie: can't unbundle pre_s cookie uri: %s\n", p->uri);
	p->failed = PBC_BAD_AUTH;
	return -1;
    }
 
    return((*cookie_data).broken.pre_sess_token);

}

VOID Clear_Cookie(HTTP_FILTER_CONTEXT* pFC, char* cookie_name, char* cookie_domain, char* cookie_path, bool secure)
{

	char new_cookie[START_COOKIE_SIZE];
	char secure_string[16];
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

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

		filterlog(p, LOG_INFO,"  Cleared Cookie %s\n",cookie_name);
}

int Redirect(HTTP_FILTER_CONTEXT* pFC, char* RUrl) {
    char    szBuff[2048];
	DWORD	dwBuffSize;
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

    sprintf(szBuff,"Content-Type: text/html\r\n");
		
	filterlog(p, LOG_INFO," Redirect to %s",RUrl);

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

int Add_Post_Data(HTTP_FILTER_CONTEXT* pFC, unsigned char* greq) {

    char    szBuff[2048];
	DWORD	dwBuffSize;
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

    sprintf(szBuff,"Content-Type: text/html\r\n");
		
	filterlog(p, LOG_INFO," Adding POST data");

	pFC->AddResponseHeaders(pFC,szBuff,0);

	pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
		"200 OK",NULL,NULL);

	sprintf(szBuff, "<html>\r\n"
					" <body onLoad=\"document.relay.submit()\">\r\n"
					"  <form method=post action=\"%s\" name=relay>\r\n\r\n"
					"   <input type=hidden name=pubcookie_g_req value=\"%s\">\r\n"
					"   <input type=hidden name=relay_url value=\"%s\">\r\n\r\n"
					"   <noscript>\r\n"
					"    <p align=center>You do not have Javascript enabled.\r\n"
					"       Please click the button to continue.</p>\r\n"
					"    <p align=center> <input type=submit name=go value=\"Continue\"></p>\r\n"
					"   </noscript>\r\n\r\n"
					"  </form>\r\n"
					" </body>\r\n"
					"</html>\r\n",p->Login_URI,greq,p->Relay_URI);
	
	dwBuffSize=strlen(szBuff);

	pFC->WriteClient (pFC, szBuff, &dwBuffSize, 0);

	return OK;

}

BOOL Pubcookie_Init () 
{
	int rslt;
	pubcookie_dir_rec *p=NULL;
	DWORD tmpsz = 256;

	p = (pubcookie_dir_rec *)malloc(sizeof(pubcookie_dir_rec));
	bzero(p,sizeof(pubcookie_dir_rec));

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
	if (!libpbc_pubcookie_init(p,&default_context)) {  
		return FALSE;
	}

	free(p);
    return TRUE;

}  /* Pubcookie_Init */

// 'X' out the pubcookie cookies so the web page can't see them.  
//  Not used.  Xed out cookies cause problems with pubcookie logic.
//  Clear them instead
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
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_INFO," Blank_Cookie\n"); 

	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pHeaderInfo->GetHeader(pFC,"Cookie:",cookie_data,&cbSize)) {
		dwError = GetLastError();
		filterlog(p, LOG_INFO," GetHeader[Cookie:] failed = %d (%x), buffer size= %d\n",
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


int Hide_Cookies (HTTP_FILTER_CONTEXT* pFC,  //This function no longer needed
					  HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
 /*   pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_INFO," Hide_Cookies\n");

	Blank_Cookie(pFC, pHeaderInfo, PBC_S_COOKIENAME);
    Blank_Cookie(pFC, pHeaderInfo, PBC_G_COOKIENAME);
*/
    return OK;

} /* Hide_Cookies */



void Add_No_Cache(HTTP_FILTER_CONTEXT* pFC)
{
	char			szHeaders[PBC_1K];

	sprintf(szHeaders, 
			"Cache-Control: no-store, no-cache, must-revalidate\r\n"
			"Pragma: no-cache\r\n"
			"Expires: %s\r\n", EARLIEST_EVER);
			
		  
	pFC->AddResponseHeaders(pFC,szHeaders,0);

}
void Add_Cookie (HTTP_FILTER_CONTEXT* pFC, char* cookie_name, unsigned char* cookie_contents, char* cookie_domain)
{
	char			szHeaders[PBC_1K];
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_INFO,"  Adding cookie %s\n   domain=%s;\n   path=/;\n   secure;\n",cookie_name,cookie_domain);

	snprintf(szHeaders, PBC_1K, "Set-Cookie: %s=%s; domain=%s; path=/; secure\r\n",
		cookie_name, 
		cookie_contents,
		cookie_domain);

	pFC->AddResponseHeaders(pFC,szHeaders,0);

}

//handles cases where pubc authn failed. sets pression & granting requests and ships browser to login server.
int Auth_Failed (HTTP_FILTER_CONTEXT* pFC) 
{
	char 			args[PBC_4K];
	char 			g_req_contents[PBC_4K];
	unsigned char	e_g_req_contents[PBC_4K];
	char			szTemp[PBC_1K];
    unsigned char   *pre_s;
	int				pre_sess_tok;

	pubcookie_dir_rec* p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_INFO," Auth_Failed\n");

	/* reset these dippy flags */
	p->failed = 0;

	/* deal with GET args */
	if ( strlen(p->args) > 0 ) {
		if ( strlen(p->args) > sizeof(args) ) {  // ?? does base64 double size ??
			filterlog(p, LOG_ERR,"[Pubcookie_Init] Invalid Args Length = %d; remote_host: %s",
				strlen(p->args), p->remote_host);
			strcpy(args, "");
		} else
			libpbc_base64_encode(p, (unsigned char *)p->args, (unsigned char *)args,
						strlen(p->args));
		}
	else
		strcpy(args, "");

	strcpy(szTemp,p->appsrvid); 
	if ( strlen(p->appsrv_port) > 0 ) {
		strcat(szTemp,":");
		strcat(szTemp,p->appsrv_port);
	}
    if( (pre_sess_tok=get_pre_s_token(pFC)) == -1 ) { //make presession token; a number
		filterlog(p, LOG_ERR,"Security Warning:  Unable to randomize pre-session cookie!");
        return(OK);
    }

  
	
	/* make the granting request */
	sprintf(g_req_contents, 
		"%s=%s&%s=%s&%s=%c&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%d&%s=%d&%s=%c", 
		PBC_GETVAR_APPSRVID,
		  p->server_hostname,   // Need full domain name 
		PBC_GETVAR_APPID,
		  p->appid,
		PBC_GETVAR_CREDS, 
		  p->AuthType, 
		PBC_GETVAR_VERSION, 
		  PBC_VERSION, 
		PBC_GETVAR_METHOD, 
		  p->method, 
		PBC_GETVAR_HOST, 
		  szTemp,
		PBC_GETVAR_URI, 
		  p->uri,
		PBC_GETVAR_ARGS, 
		  args,
		PBC_GETVAR_SESSION_REAUTH,
		  p->session_reauth,
		PBC_GETVAR_PRE_SESS_TOK,
		  pre_sess_tok,
          PBC_GETVAR_FLAG,
		  p->no_prompt ? 'Q' : '0');

	filterlog(p, LOG_DEBUG,"Granting Request:\n%s",g_req_contents); 

	libpbc_base64_encode(p, (unsigned char *)g_req_contents, (unsigned char *)e_g_req_contents,
				strlen(g_req_contents)); //to avoid illegal cookie characters

#ifdef PBC_USE_GET_METHOD
	Add_Cookie(pFC, PBC_G_REQ_COOKIENAME, e_g_req_contents, p->appsrvid);
#endif

	/* make the pre-session cookie ; sign it*/
    pre_s = libpbc_get_cookie(  
		p,
		p->sectext,
		(unsigned char *) "presesuser",
		PBC_COOKIE_TYPE_PRE_S, 
		PBC_CREDS_NONE, 
		pre_sess_tok,
		(unsigned char *)p->server_hostname, 
		(unsigned char *)p->appid,
		p->server_hostname,
		0);
	
    Add_Cookie (pFC,PBC_PRE_S_COOKIENAME,pre_s,p->appsrvid);
	
	Add_No_Cache(pFC);

#ifdef PBC_USE_GET_METHOD
	snprintf(szTemp,1024,p->Login_URI);
	return (Redirect(pFC,szTemp));
#else
	// POST directly to login server
	snprintf(szTemp,1024,"https://%s/%s?appsrvid=%s",p->appsrvid,PBC_POST_NAME,p->appsrvid);
	p->Relay_URI = strdup(szTemp);
	Add_Post_Data(pFC, e_g_req_contents);
	free(p->Relay_URI);
	return OK;
#endif


}  /* Auth_Failed */


int Bad_User (HTTP_FILTER_CONTEXT* pFC)
{
	char szTemp[1024];
	DWORD dwSize;
	pubcookie_dir_rec* p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;


	filterlog(p, LOG_INFO," Bad_User\n"); 

	if ( strlen(p->Error_Page) == 0 ) {

		pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
								"200 OK",NULL,NULL);

		sprintf(szTemp,"<B> User Authentication Failed!<br><br>"
			           " Please contact <a href=\"mailto:ntadmin@%s\">ntadmin@%s</a> </B> <br>",
			p->server_hostname,p->server_hostname);
		dwSize=strlen(szTemp);

		pFC->WriteClient (pFC, szTemp, &dwSize, 0);

	} else {
		Redirect(pFC, p->Error_Page);
	}

	return OK;

}  /* Bad_User */


int Is_Pubcookie_Auth (pubcookie_dir_rec *p)
{
	if ( p->AuthType != AUTH_NONE ) {
		filterlog(p, LOG_INFO," Is_Pubcookie_Auth: True");
		return TRUE;
	}
	else {
		filterlog(p, LOG_INFO," Is_Pubcookie_Auth: False");
		return FALSE;
	}

}  /* Is_Pubcookie_Auth */


/* a is from the cookie                                                       */
/* b is from the module                                                       */
int Pubcookie_Check_Version (HTTP_FILTER_CONTEXT* pFC, unsigned char *a, unsigned char *b) 
{
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_DEBUG," Pubcookie_Check_Version\n");

	if ( a[0] == b[0] && a[1] == b[1] )
		return 1;
	if ( a[0] == b[0] && a[1] != b[1] ) {
		filterlog(p, LOG_ERR,"[Pubcookie_Check_Version] Minor version mismatch cookie: %s your version: %s", a, b);
		return 1;
	}

	return 0;

}  /* Pubcookie_Check_Version */


/* check and see if whatever has timed out                                    */
int Pubcookie_Check_Exp(HTTP_FILTER_CONTEXT* pFC, time_t fromc, int exp)
{
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( (fromc + exp) > time(NULL) ) {
		filterlog(p, LOG_INFO," Pubcookie_Check_Exp: True");
		return 1;
	}
	else {
		filterlog(p, LOG_INFO," Pubcookie_Check_Exp: False");
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
    pubcookie_dir_rec   *p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pFC->GetServerVariable(pFC,"HTTP_COOKIE",cookie_data,&cbSize)) {
		dwError = GetLastError();
		filterlog(p, LOG_DEBUG," GetServerVariable[HTTP_COOKIE] failed = %d (%x), buffer size= %d\n",
			dwError,dwError,cbSize);
		if ( dwError == ERROR_INSUFFICIENT_BUFFER) {  // Should quit if too much cookie
			filterlog(p, LOG_ERR,"[Get_Cookie] Cookie Data too large : %d", cbSize);
	//		return ERROR_INSUFFICIENT_BUFFER
		}
	//	else	
		return NULL;
	}

    /* add an equal on the end of cookie name */
	strcpy(name_w_eq,name);
	strcat(name_w_eq,"=");

	filterlog(p, LOG_DEBUG,"  Looking for cookie name '%s' in (%d) (first 3000 bytes)\n%.3000s\n",
		name_w_eq,strlen(cookie_data),cookie_data);

	/* find the one that's pubcookie */

    if (!(cookie_header = strstr(cookie_data, name_w_eq))) {

		filterlog(p, LOG_INFO, " Get_Cookie: %s : Not Found",name);
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
		filterlog(p, LOG_ERR,"[Get_Cookie] Error allocating memory");
		return NULL;
	}

	strcpy(cookie,cookie_header);

		filterlog(p, LOG_INFO, " Get_Cookie: %s : Found",name);

	return cookie;

}  /* Get_Cookie */

char *Get_Ext_Cookie (EXTENSION_CONTROL_BLOCK* pECB, pubcookie_dir_rec* p, char *name)
{

	char *cookie_header;
	char cookie_data[MAX_COOKIE_SIZE+1];
	char name_w_eq [256];
	char *cookie, *ptr;
	DWORD cbSize, dwError;

	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pECB->GetServerVariable(pECB->ConnID,"HTTP_COOKIE",cookie_data,&cbSize)) {
		dwError = GetLastError();
		syslog(LOG_DEBUG," GetServerVariable[HTTP_COOKIE] failed = %d (%x), buffer size= %d\n",
			dwError,dwError,cbSize);
		if ( dwError == ERROR_INSUFFICIENT_BUFFER) {  // Should quit if too much cookie
			syslog(LOG_ERR,"[Get_Ext_Cookie] Cookie Data too large : %d", cbSize);
	//		return ERROR_INSUFFICIENT_BUFFER
		}
	//	else	
		return NULL;
	}

    /* add an equal on the end of cookie name */
	strcpy(name_w_eq,name);
	strcat(name_w_eq,"=");

	syslog(LOG_DEBUG,"  Looking for cookie name '%s' in (%d) (first 3000 bytes)\n%.3000s\n",
		name_w_eq,strlen(cookie_data),cookie_data);

	/* find the one that's pubcookie */

    if (!(cookie_header = strstr(cookie_data, name_w_eq))) {

		syslog(LOG_INFO, " Get_Cookie: %s : Not Found",name);
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
		syslog(LOG_ERR,"[Get_Cookie] Error allocating memory");
		return NULL;
	}

	strcpy(cookie,cookie_header);

		syslog( LOG_INFO, " Get_Cookie: %s : Found",name);

	return cookie;

}  /* Get_Ext_Cookie */

void Read_Reg_Values (char *key, pubcookie_dir_rec* p)
{
	HKEY hKey;
	DWORD dwRead;
	long rslt;
	char authname[512];

	if (rslt = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		key,0,KEY_READ,&hKey) == ERROR_SUCCESS)
	{
		dwRead = sizeof (p->pszUser);
		RegQueryValueEx (hKey, "NTUserId",
			NULL, NULL, (LPBYTE) p->pszUser, &dwRead);
		
		dwRead = sizeof (p->pszPassword);
		RegQueryValueEx (hKey, "Password", 
			NULL, NULL, (LPBYTE) p->pszPassword, &dwRead);
		
		dwRead = sizeof (p->inact_exp);
		RegQueryValueEx (hKey, "Inactive_Timeout",
			NULL, NULL, (LPBYTE) &p->inact_exp, &dwRead);
		
		dwRead = sizeof (p->hard_exp);
		RegQueryValueEx (hKey, "Hard_Timeout",
			NULL, NULL, (LPBYTE) &p->hard_exp, &dwRead);
		
		dwRead = sizeof (p->force_reauth);
		RegQueryValueEx (hKey, "Force_Reauth",
			NULL, NULL, (LPBYTE) p->force_reauth, &dwRead);
		
		dwRead = sizeof (p->session_reauth);
		RegQueryValueEx (hKey, "Session_Reauth",
			NULL, NULL, (LPBYTE) &p->session_reauth, &dwRead);

		dwRead = sizeof (p->no_prompt);
		RegQueryValueEx (hKey, "No_Prompt",
			NULL, NULL, (LPBYTE) &p->no_prompt, &dwRead);
		
		dwRead = sizeof (p->logout_action);
			RegQueryValueEx (hKey, "Logout_Action",
							 NULL, NULL, (LPBYTE) &p->logout_action, &dwRead);
		
		dwRead = sizeof (authname); authname[0] = NULL;
		RegQueryValueEx (hKey, "AuthType",
			NULL, NULL, (LPBYTE) authname, &dwRead);
		if ( strlen(authname) > 0 ) {
			if ( stricmp(authname,(PBC_AUTHTYPE1)) == 0 ) 
				p->AuthType = '1';
			else
				if ( stricmp(authname,(PBC_AUTHTYPE2))== 0 ) 
					p->AuthType = '2';
				else
					if ( stricmp(authname,(PBC_AUTHTYPE3))== 0 ) 
						p->AuthType = '3';
					else
						if ( stricmp(authname,(PBC_AUTHTYPE0)) == 0 )
							p->AuthType = '0';
		}

		dwRead = sizeof (p->default_url);
		RegQueryValueEx (hKey, "Default_Url",
			NULL, NULL, (LPBYTE) p->default_url, &dwRead);
		
		dwRead = sizeof (p->timeout_url);
		RegQueryValueEx (hKey, "Timeout_Url",
			NULL, NULL, (LPBYTE) p->timeout_url, &dwRead);
		
		dwRead = sizeof (p->Login_URI);
		RegQueryValueEx (hKey, "Web_Login",
			NULL, NULL, (LPBYTE) p->Login_URI, &dwRead);
		RegQueryValueEx (hKey, "Login_URI",
			NULL, NULL, (LPBYTE) p->Login_URI, &dwRead);

		dwRead = sizeof (p->Enterprise_Domain);
		RegQueryValueEx (hKey, "Enterprise_Domain",
			NULL, NULL, (LPBYTE) p->Enterprise_Domain, &dwRead);

		dwRead = sizeof (p->Error_Page);
		RegQueryValueEx (hKey, "Error_Page",
			NULL, NULL, (LPBYTE) p->Error_Page, &dwRead);

		dwRead = sizeof (p->Set_Server_Values);
		RegQueryValueEx (hKey, "SetHeaderValues",
			NULL, NULL, (LPBYTE) &p->Set_Server_Values, &dwRead);

#	ifndef COOKIE_PATH
		dwRead = sizeof (p->appid);
		RegQueryValueEx (hKey, "AppId",
			NULL, NULL, (LPBYTE) p->appid, &dwRead);
#	endif		
		
		if (p->logout_action != LOGOUT_NONE) {   //Local logout cannot be authenticated. Redirect could, but isn't
			p->AuthType = AUTH_NONE;
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
	pubcookie_dir_rec* p;
	DWORD dwBufferSize = 1024;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	// Initialize default values  
	// These can be overriden in /default

	p->inact_exp = PBC_DEFAULT_INACT_EXPIRE;
	p->hard_exp  = PBC_DEFAULT_HARD_EXPIRE;

	strcpy(p->pszUser,"");
	strcpy(p->pszPassword,"");
	strcpy(p->force_reauth,PBC_NO_FORCE_REAUTH);
	p->session_reauth = 0;
	p->no_prompt = 0;
	p->AuthType = AUTH_NONE;
	p->logout_action = LOGOUT_NONE;
	strcpy(p->Enterprise_Domain,(PBC_ENTRPRS_DOMAIN));
	strcpy(p->Login_URI, (PBC_LOGIN_URI));
	strcpy(p->Error_Page,"");
	p->Set_Server_Values = false;
	p->legacy = false;
	
    // Then Look in default key
	
	strcpy (key, (PBC_WEB_VAR_LOCATION));
	strcat (key,"\\");
	strcat (key, PBC_DEFAULT_KEY);

	Read_Reg_Values (key, p);


	// Then first node (current appid)

	strcpy (key, PBC_WEB_VAR_LOCATION);
	strcat (key,"\\");
	strcat (key, p->appid);

	Read_Reg_Values (key, p);

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
				p->AuthType = AUTH_NETID;
				p->legacy = true;
				filterlog(p, LOG_INFO,"  dir type       : %s\n",szBuff);
			}
			else if ( stricmp((const char *)szBuff, (PBC_SECURID_NAME)) == 0 ) {
				p->AuthType = AUTH_SECURID;
				p->legacy = true;
				filterlog(p, LOG_INFO,"  dir type       : %s\n",szBuff);
			}
			else if ( stricmp((const char *)szBuff, (PBC_PUBLIC_NAME)) == 0 ) {
				p->AuthType = AUTH_NONE;
				p->Set_Server_Values = true;
				p->legacy = true;
				filterlog(p, LOG_INFO,"  dir type       : %s\n",szBuff);
			}
		}

		strcat (key, "\\");
		strcat (key, szBuff);

		Read_Reg_Values (key, p);

	}

#ifndef COOKIE_PATH
	// Convert appid to lower case
	strlwr(p->appid);
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
			"    No_Prompt        :	%1d\n" 
			"    Logout_Action    : %1d\n" 
			"    AuthType         : %c\n" 
			"    Default_Url      : %s\n" 
			"    Timeout_Url      : %s\n" 
			"    Login_URI        : %s\n" 
			"    Enterprise_Domain: %s\n" 
			"    Error_Page       : %s\n" 
			"    Set_Server_Values: %d\n",
			key,
			p->appid,
			p->pszUser,
			(strlen(p->pszPassword) > 0),
			p->inact_exp,
			p->hard_exp,
			p->force_reauth,
			p->session_reauth,
			p->no_prompt,
			p->logout_action,
			p->AuthType,
			p->default_url,
			p->timeout_url,
			p->Login_URI,
			p->Enterprise_Domain,
			p->Error_Page,
			p->Set_Server_Values);
		
	filterlog(p, LOG_INFO,buff);
	}
	sprintf(p->s_cookiename,"%s_%s",PBC_S_COOKIENAME,p->appid);

} 


void Add_Header_Values(HTTP_FILTER_CONTEXT* pFC,
					   HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char temp[16];
	pubcookie_dir_rec* p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	// Set Pubcookie Appid, User and Creds level

	pHeaderInfo->AddHeader(pFC,PBC_Header_Server,p->server_hostname);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Appid,p->appid);

//	pHeaderInfo->SetHeader(pFC,"REMOTE_USER",p->user);
// Don't know how to override server variables so use our own

	pHeaderInfo->AddHeader(pFC,PBC_Header_User,p->user);

	sprintf(temp,"%c",p->AuthType);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Creds,temp);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Version,Pubcookie_Version);

}  /* Add_Header_Values */

bool MakeSecContext(HTTP_FILTER_CONTEXT* pFC,			
					pubcookie_dir_rec *p)
{

    /* the granting certificate */
    char *g_certfile;
    /* our crypt key */
    char *cryptkeyfile = NULL;
	size_t cb_read;
    FILE *fp;

	//GetUserName(username,&usize);
	//filterlog(p, LOG_DEBUG,"Creating security context for user: %s ",username);
	//Use AllocMem so this gets freed eventually
	p->sectext = (security_context *)pFC->AllocMem(pFC,sizeof(security_context),0);

	p->sectext->sess_key  = default_context->sess_key;
	p->sectext->sess_cert = default_context->sess_cert;
	p->sectext->sess_pub = default_context->sess_pub;
	p->sectext->myname = p->server_hostname;

    g_certfile = strdup(libpbc_config_getstring(p, "granting_cert_file", NULL));

    if (!g_certfile) {
        g_certfile = (char *)pbc_malloc(p, 1025); 
        snprintf(g_certfile, 1024, "%s\\%s", PBC_KEY_DIR,
                 "pubcookie_granting.cert");
    }

    /* test g_certfile; it's a fatal error if this isn't found */
    if (access(g_certfile, R_OK | F_OK)) {
        filterlog(p, LOG_ERR, 
                         "security_context: couldn't find granting certfile (try setting granting_cert_file?): tried %s", g_certfile);
        return false;
    }

    /* granting cert */
    fp = pbc_fopen(p, g_certfile, "r");
    if (!fp) {
	filterlog(p, LOG_ERR, 
                         "security_context: couldn't read granting certfile: pbc_fopen %s", 
                         g_certfile); 
	return false;
    }
    p->sectext->g_cert = (X509 *) PEM_read_X509(fp, NULL, NULL, NULL);
    if (!p->sectext->g_cert) {
	filterlog(p, LOG_ERR, 
                         "security_context: couldn't parse granting certificate: %s", g_certfile);
	return false;
    }
    p->sectext->g_pub = X509_extract_key(p->sectext->g_cert);

    pbc_fclose(p, fp);

    /* our crypt key */
    cryptkeyfile = (char *)libpbc_config_getstring(p, "crypt_key", NULL);
    if (cryptkeyfile) {
        if (access(cryptkeyfile, R_OK | F_OK) == -1) {
            filterlog(p, LOG_ERR, "security_context: can't access crypt key file %s, will try standard location", cryptkeyfile);
            pbc_free(p, cryptkeyfile);
            cryptkeyfile = NULL;
        }
    }
    if (!cryptkeyfile) {
        cryptkeyfile = (char *)pbc_malloc(p, 1024);
        make_crypt_keyfile(p, p->sectext->myname, cryptkeyfile);
        if (access(cryptkeyfile, R_OK | F_OK) == -1) {
            filterlog(p, LOG_ERR, "security_context: can't access crypt key file %s (try setting crypt_key)", cryptkeyfile);
            free(cryptkeyfile);
            return false;
        }
    }

    fp = pbc_fopen(p, cryptkeyfile, "rb");
    if (!fp) {
        filterlog(p, LOG_ERR, "security_context: couldn't read crypt key: pbc_fopen %s: %m", cryptkeyfile);
        return false;
    }

    if( cb_read = fread(p->sectext->cryptkey, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
        filterlog(p, LOG_ERR,
			"can't read crypt key %s: short read: %d", cryptkeyfile, cb_read);
        pbc_fclose(p, fp);
        return false;
    }

    pbc_fclose(p, fp);
    if (g_certfile != NULL)
        pbc_free(p, g_certfile);

	free(cryptkeyfile);
    
    return true;
}


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
	pubcookie_dir_rec* p;
	int pre_sess_from_cookie;

    p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_INFO," Pubcookie_User\n");

    // First check to see if this directory needs protection

	// Fetch requested URL

    pHeaderInfo->GetHeader(pFC,"url",achUrl,&cbURL);

	filterlog(p, LOG_INFO,"  Requested URL : %s\n",achUrl);

	// Have to parse Query_String ourselves, server hasn't scanned it yet

	ptr = strchr(achUrl,'?');
	if (ptr) {
		*ptr++;
		strncpy(szBuff, ptr, strlen(ptr));
		szBuff[strlen(ptr)] = NULL;
		strcpy(p->args,szBuff);
		filterlog(p, LOG_INFO,"  Query String  : %s\n",szBuff);
	}
	// Else dfcg->args[0]=NULL because of original memset

	// Normalize the URL - take out all those nasty ../ and %xx

	pFC->ServerSupportFunction(pFC,SF_REQ_NORMALIZE_URL,
								achUrl,NULL,NULL);

	filterlog(p, LOG_DEBUG,"  Normalized URL: %s\n",achUrl);

	// set Uri
	strcpy(p->uri,achUrl);

	// set Request Method
	dwBuffSize = sizeof(p->method);
	pHeaderInfo->GetHeader(pFC,"method",p->method,&dwBuffSize);

	filterlog(p, LOG_INFO,"  Request Method: %s\n",p->method);

	// Get Application ID from first node

	strcpy((char *)p->appid,(PBC_DEFAULT_APP_NAME));
	p->user[0]  = NULL;
	p->AuthType    = AUTH_NONE;

	pachUrl = achUrl;

	if ( PBC_IGNORE_POLL && strlen(pachUrl) == 1 ) {
		// Don't care about "/" - Possibly Network Dispatcher Polling
		return DECLINED;
	}

    *pachUrl++;		// skip over first '/'
    ptr = strchr(pachUrl,'/');
	if ( ptr ) {
		strncpy((char *)p->appid, pachUrl, ptr-pachUrl);
		p->appid[(ptr-pachUrl)] = NULL;
	}
	else if (strlen(pachUrl) > 0) {   // This could set appid to a filename in the root dir
		strcpy((char *)p->appid, pachUrl);
	}
    
	// Don't loop trying to protect virtual post name
	if (!stricmp(PBC_POST_NAME,p->appid)) {
				return DECLINED;
	}
	// Save Path unchanged so cookies will be returned properly
	// strcpy(p->path_id,p->appid);

	// Get userid, timeouts, AuthType, etc for this app.  Could change appid.
	Get_Effective_Values(pFC,pHeaderInfo,ptr);

	/* Log out if indicated */

	if (p->logout_action > LOGOUT_NONE) {
#ifdef COOKIE_PATH
		if ( stricmp(p->appid,(PBC_DEFAULT_APP_NAME)) == 0 )
			strcpy(szBuff,"/");
		else 
			sprintf(szBuff,"/%s",p->appid);
#else
		strcpy(szBuff,"/");
#endif
		//  If we're logging out, clear the cookie.
		
		Clear_Cookie(pFC,p->s_cookiename,p->appsrvid,szBuff,FALSE); 
		
		if (p->logout_action == LOGOUT_REDIRECT || p->logout_action == LOGOUT_REDIRECT_CLEAR_LOGIN) {
			
			filterlog(p, LOG_INFO,"  Logout Redirect....\n");
			
			sprintf(szBuff, "%s?%s=%d&%s=%s&%s=%s",
				p->Login_URI,
				PBC_GETVAR_LOGOUT_ACTION,
				(p->logout_action == LOGOUT_REDIRECT_CLEAR_LOGIN ? LOGOUT_ACTION_CLEAR_L : LOGOUT_ACTION_NOTHING),
				PBC_GETVAR_APPID,
				p->appid,
				PBC_GETVAR_APPSRVID,
				p->appsrvid);
			
			
			p->failed = PBC_LOGOUT_REDIR;
			p->handler = PBC_LOGOUT_REDIR;
			
			return (Redirect(pFC, szBuff));
			
		}
		else {
			return DECLINED;  // continue serving the logout page if we're not redirecting
		}
	}

	/* We're done if this is an unprotected page */
	if (p->AuthType == AUTH_NONE) {
		if (p->Set_Server_Values) {
			Add_Header_Values   (pFC,pHeaderInfo);
		}
		return DECLINED;
	}

	// Fill in security context
	if (!MakeSecContext(pFC, p)) {
		syslog(LOG_ERR,"[PBC_OnPreprocHeaders] Error creating security context");
		p->failed = PBC_BAD_GRANTING_CERT;
		return OK;
	}

	// Can't see cookies unless we are SSL. Redirect to https if needed.

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT_SECURE",
							szBuff, &dwBuffSize);
	if ( strcmp(szBuff,"0") == 0 ) 
	{
		p->failed = PBC_BAD_PORT;
		sprintf(szBuff,"https://%s%s%s%s",p->appsrvid, achUrl,(strlen(p->args) ? "?" : ""), p->args);
		return(Redirect(pFC,szBuff));
	}



	filterlog(p, LOG_INFO,"  creds= %c\n",p->AuthType);


	// Set force reauth URL to requested URL if not "NFR"
	if ( strcmp(p->force_reauth,PBC_NO_FORCE_REAUTH) != 0 )
		if ( strlen(p->default_url) > 0 )
			strcpy((char *)p->force_reauth,p->default_url);
		else
			strcpy((char *)p->force_reauth,achUrl);

    // Get Granting cookie or Session cookie
	// If '<cookie name>=' then client has bogus time and cleared cookie hasn't expired

	if( !(cookie = Get_Cookie(pFC,PBC_G_COOKIENAME)) || (strcmp(cookie,"")==0) ) {
		if (cookie) pbc_free(p, cookie);
		if( !(cookie = Get_Cookie(pFC,p->s_cookiename)) || (strcmp(cookie,"")==0) ) {
			filterlog(p, LOG_INFO,"  Pubcookie_User: no cookies yet, must authenticate\n");
			if (cookie) pbc_free(p, cookie);
			p->failed = PBC_BAD_AUTH;
			return OK;
		}
		else {

			if( ! (cookie_data = libpbc_unbundle_cookie(p, p->sectext, cookie, p->server_hostname, false)) ) {
				filterlog(p, LOG_ERR,"[Pubcookie_User] Can't unbundle Session cookie for URL %s; remote_host: %s",
					p->uri, p->remote_host);
				p->failed = PBC_BAD_SESSION_CERT;
				pbc_free(p, cookie);
				return OK;
			}
		else {
			p->cookie_data = cookie_data;
		}

		pbc_free(p, cookie);

		filterlog(p, LOG_INFO,"  Session Cookie Contents:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    create_ts= %d\n    last_ts= %d\n",
			(*cookie_data).broken.user,(*cookie_data).broken.version,(*cookie_data).broken.appsrvid,
			(*cookie_data).broken.appid,(*cookie_data).broken.type,(*cookie_data).broken.creds,
			(*cookie_data).broken.create_ts,(*cookie_data).broken.last_ts);

		strcpy(p->user, (char *)(*cookie_data).broken.user);

		// maintain highest level of creds
		if ( p->AuthType == AUTH_NETID && (*cookie_data).broken.creds == AUTH_SECURID )
			 p->AuthType = AUTH_SECURID;

		if( ! Pubcookie_Check_Exp(pFC,(*cookie_data).broken.create_ts,p->hard_exp)) {
			filterlog(p, LOG_INFO,"  Session cookie hard expired for user: %s create_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.create_ts,
                p->hard_exp,
                (time(NULL)-(*cookie_data).broken.create_ts) );
			if ( strcmp(p->force_reauth,PBC_NO_FORCE_REAUTH) != 0 &&
				 strlen(p->timeout_url) > 0 )
				strcpy((char *)p->force_reauth,p->timeout_url);
			p->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}
		else {
			filterlog(p, LOG_INFO,"  Session cookie not hard expired for user: %s create_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.create_ts,
                p->hard_exp,
                (time(NULL)-(*cookie_data).broken.create_ts) );
		}

		if(p->inact_exp != -1 &&
			! Pubcookie_Check_Exp(pFC,(*cookie_data).broken.last_ts,p->inact_exp) ) {
			filterlog(p, LOG_INFO,"  Session cookie inact expired for user: %s last_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.last_ts,
                p->inact_exp,
                (time(NULL)-(*cookie_data).broken.last_ts) );
			if ( strcmp(p->force_reauth,PBC_NO_FORCE_REAUTH) != 0 &&
				 strlen(p->timeout_url) > 0 )
				strcpy((char *)p->force_reauth,p->timeout_url);
			p->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}

		} /* end if session cookie */

	}
	else {

		p->has_granting = 1;

		/* the granting cookie gets blanked too early and another login */
		/* server loop is required, this just speeds up that loop */
		/*if( strncmp(cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0 ) {
			p->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie);
			return OK;
		}*/ 		/* PBC_X_STRING doesn't seem to be used any longer */


		if( !(cookie_data = libpbc_unbundle_cookie(p, p->sectext, cookie, p->server_hostname, true)) ) {
			filterlog(p, LOG_ERR,"[Pubcookie_User] Can't unbundle Granting cookie for URL %s; remote_host: %s", 
				p->uri, p->remote_host);
			p->failed = PBC_BAD_GRANTING_CERT;
			pbc_free(p, cookie);
			return OK;
		}

		/* check pre_session cookie */
		pre_sess_from_cookie = get_pre_s_from_cookie(pFC);
		if( (*cookie_data).broken.pre_sess_token != pre_sess_from_cookie ) {
			filterlog(p, LOG_INFO,"pubcookie_user, pre session tokens mismatched, uri: %s", p->uri);
			filterlog(p, LOG_INFO,"pubcookie_user, pre session from G: %d PRE_S: %d, uri: %s", 
				(*cookie_data).broken.pre_sess_token, pre_sess_from_cookie, p->uri);
			p->failed = PBC_BAD_AUTH;
			return OK;
		}

		pbc_free(p, cookie);

		filterlog(p, LOG_INFO,"  Granting Cookie Contents:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    create_ts= %d\n    last_ts= %d\n",
			(*cookie_data).broken.user  ,(*cookie_data).broken.version  ,(*cookie_data).broken.appsrvid,
			(*cookie_data).broken.appid,(*cookie_data).broken.type     ,(*cookie_data).broken.creds,
			(*cookie_data).broken.create_ts,(*cookie_data).broken.last_ts);

		strcpy(p->user,(const char *)(*cookie_data).broken.user);

		// maintain highest level of creds
		if ( p->AuthType == AUTH_NETID && (*cookie_data).broken.creds == AUTH_SECURID )
			 p->AuthType = AUTH_SECURID;

		if( ! Pubcookie_Check_Exp(pFC,(*cookie_data).broken.create_ts, PBC_GRANTING_EXPIRE) ) {
			filterlog(p, LOG_INFO,"[Pubcookie_User] Granting cookie expired for user: %s  elapsed: %d limit: %d; remote_host: %s", 
				(*cookie_data).broken.user,(time(NULL)-(*cookie_data).broken.create_ts), PBC_GRANTING_EXPIRE, p->remote_host);
			p->failed = PBC_GRANTING_TIMEOUT;
			pbc_free(p, cookie_data);
			return OK;
		}

	} /* end if granting cookie */

	/* check appid */
	current_appid = p->appid;
	if( _strnicmp((const char *)current_appid, (const char *)(*cookie_data).broken.appid, 
					sizeof((*cookie_data).broken.appid)-1) != 0 ) {
	//	filterlog(p, LOG_ERR,"[Pubcookie_User] Wrong appid; current: %s cookie: %s; remote_host: %s", 
	//		current_appid, (*cookie_data).broken.appid, p->remote_host);
		p->failed = PBC_BAD_AUTH;   // PBC_BAD_APPID;  // Left over from failed application
		pbc_free(p, cookie_data);
		return OK;
	}

	/* make sure this cookie is for this server */
	/* Use server_hostname instead of appsrvid so we only need one c_key per server */
	if( _strnicmp((const char *)p->server_hostname, (const char *)(*cookie_data).broken.appsrvid, 
					sizeof((*cookie_data).broken.appsrvid)-1) != 0 ) {
		filterlog(p, LOG_WARN,"[Pubcookie_User] Wrong app server id; current: %s cookie: %s; remote_host: %s", 
				p->server_hostname, (*cookie_data).broken.appsrvid, p->remote_host);
		p->failed = PBC_BAD_AUTH;  // PBC_BAD_SERVERID;
		pbc_free(p, cookie_data);
		return OK;  
	}

	if( !Pubcookie_Check_Version(pFC,(*cookie_data).broken.version, 
			(unsigned char *)PBC_VERSION)){
		filterlog(p, LOG_ERR,"[Pubcookie_User] Wrong version id; module: %d cookie: %d", 
				PBC_VERSION, (*cookie_data).broken.version);
		p->failed = PBC_BAD_VERSION;
		pbc_free(p, cookie_data);
		return OK;
	}

	if(p->AuthType == AUTH_NETID ) {
		if( (*cookie_data).broken.creds != AUTH_NETID &&
			(*cookie_data).broken.creds != AUTH_SECURID    ) {
			filterlog(p, LOG_ERR,"[Pubcookie_User] Wrong creds directory; %c cookie: %c", 
				AUTH_NETID, (*cookie_data).broken.creds);
			p->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		} else {
			p->AuthType = (*cookie_data).broken.creds;   // Use Creds from Cookie
			}
	}
	else
	if(p->AuthType == AUTH_SECURID ) {
		if( (*cookie_data).broken.creds != AUTH_SECURID ) {
			filterlog(p, LOG_ERR,"  Pubcookie_User: Wrong creds directory; %c cookie: %c", 
				AUTH_SECURID, (*cookie_data).broken.creds);
			p->failed = PBC_BAD_AUTH;
			pbc_free(p, cookie_data);
			return OK;
		}
	}

//	pbc_free(cookie_data);  /*Need this later to reset timestamp*/

	return OK;

}  /* Pubcookie_User */


int Pubcookie_Auth (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_INFO," Pubcookie_Auth\n");

	if( !Is_Pubcookie_Auth(p) ) 
		return DECLINED;

	if(p->failed)  /* Pubcookie_User has failed so pass to typer */
		return OK;

	return DECLINED;

}  /* Pubcookie_Auth */


int Pubcookie_Typer (HTTP_FILTER_CONTEXT* pFC,
					 HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo) 
{
	unsigned char	*cookie;
	int first_time_in_session = 0;
	pubcookie_dir_rec* p;
	char session_cookie_name[MAX_PATH];

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	filterlog(p, LOG_DEBUG," Pubcookie_Typer\n");

	if( p->logout_action ) 
		return OK;  //if we got here while logging out, we're redirecting
	if( !Is_Pubcookie_Auth(p) ) 
		return DECLINED;  //if we got here without auth, something must have changed midstream

	filterlog(p, LOG_INFO," Pubcookie_Typer\n Has_Granting= %d, Failed= %d\n",p->has_granting,p->failed);

	if (p->has_granting ) {

		/* clear granting and presession cookies */
		Clear_Cookie(pFC,PBC_G_COOKIENAME,p->appsrvid,"/",TRUE);
		Clear_Cookie(pFC,PBC_PRE_S_COOKIENAME,p->appsrvid,"/",TRUE);

		first_time_in_session = 1;
		p->has_granting = 0;
	}

	if (!p->failed) {
	/* if the inactivity timeout is turned off don't send a session cookie 
	everytime, but be sure to send a session cookie if it's the first time
	in the app */
		if (p->inact_exp > 0 || first_time_in_session) {
			
			if( !first_time_in_session ) {
				cookie = libpbc_update_lastts(p, p->sectext, p->cookie_data, p->server_hostname, 0);
				filterlog(p, LOG_INFO,"  Setting session cookie last timestamp to: %ld\n",p->cookie_data->broken.last_ts);
			}
			else {
				cookie = libpbc_get_cookie(p,
					p->sectext,
					(unsigned char *)p->user, 
					PBC_COOKIE_TYPE_S,
					p->AuthType,
					23,
					(unsigned char *)p->server_hostname, 
					(unsigned char *)p->appid,
					p->server_hostname,
					0);

				filterlog(p, LOG_INFO,"  Created new session cookie.\n");
			}


#ifdef COOKIE_PATH
			if ( stricmp(p->appid,(PBC_DEFAULT_APP_NAME)) == 0 )
				sprintf(new_cookie, "Set-Cookie: %s_%s=%s; domain=%s; path=/; secure\r\n", 
				PBC_S_COOKIENAME, p->appid,
				cookie, 
				p->appsrvid);
			else 
				sprintf(new_cookie, "Set-Cookie: %s_%s=%s; domain=%s; path=/%s; secure\r\n", 
				PBC_S_COOKIENAME, p->appid,
				cookie, 
				p->appsrvid,
				p->appid);

			pFC->AddResponseHeaders(pFC,new_cookie,0);

#else
			snprintf(session_cookie_name,MAX_PATH,"%s_%s",PBC_S_COOKIENAME,p->appid);
			Add_Cookie(pFC,session_cookie_name,cookie,p->appsrvid);
			
	
#endif
			pbc_free(p, cookie);
			pbc_free(p, p->cookie_data);
			
		
		}
		// Have a good session cookie at this point
		// Now set effective UserId ,UWNetID and Creds values for ASP pages
		
		Add_Header_Values(pFC,pHeaderInfo);

		return DECLINED;

	} else if (p->failed == PBC_BAD_AUTH) {
		p->handler = PBC_BAD_AUTH;
		return OK;
	} else if (p->failed == PBC_BAD_USER) {
		p->handler = PBC_BAD_USER;
		return OK;
	} else if (p->failed == PBC_FORCE_REAUTH) {
		p->handler = PBC_FORCE_REAUTH;
		return OK;
	} else if (p->failed == PBC_BAD_GRANTING_CERT) {
		p->handler = PBC_BAD_GRANTING_CERT;
		return OK;
	} else if (p->failed == PBC_BAD_CRYPT_KEY) {
		p->handler = PBC_BAD_CRYPT_KEY;
		return OK;
	} else if (p->failed == PBC_BAD_SESSION_CERT) {
		p->handler = PBC_BAD_SESSION_CERT;
		return OK;
	} else if (p->failed == PBC_BAD_VERSION) {
		p->handler = PBC_BAD_VERSION;
		return OK;
	} else if (p->failed == PBC_BAD_APPID) {
		p->handler = PBC_BAD_APPID;
		return OK;
	} else if (p->failed == PBC_BAD_SERVERID) {
		p->handler = PBC_BAD_SERVERID;
		return OK;
	} else if (p->failed == PBC_BAD_PORT) {
		p->handler = PBC_BAD_PORT;
		return OK;
	} else if (p->failed == PBC_GRANTING_TIMEOUT) {
		p->handler = PBC_GRANTING_TIMEOUT;
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
	
	// Register for notifications
	pVer->dwFlags = Notify_Flags;

	return TRUE;

}  /* GetFilterVersion */


DWORD OnReadRawData (HTTP_FILTER_CONTEXT *pFC,
                     HTTP_FILTER_RAW_DATA *pRawDataInfo)
{
	pubcookie_dir_rec* p;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	syslog(LOG_INFO,    
		"\nPBC_OnReadRawData\n"
		"  Revision: x%x\n"
		"  Secure  : x%x\n"
		,pFC->Revision,pFC->fIsSecurePort);
	/*{
		LPSTR lpRawData;
		DWORD dwRawSize;
		lpRawData = (LPSTR)pRawDataInfo->pvInData;
		dwRawSize = pRawDataInfo->cbInData;
	
		syslog(LOG_ERR, "  Read:(%d) \n%s",  
			dwRawSize,lpRawData);
	}*/
	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnReadRawData */

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile(pool *p, const char *peername, char *buf)
{

    strlcpy(buf, PBC_KEY_DIR, 1024);

    if (buf[strlen(buf)-1] != '\\') {
        strlcat(buf, "\\", 1024);
    }
    strlcat(buf, peername, 1024);

}


DWORD OnPreprocHeaders (HTTP_FILTER_CONTEXT* pFC,
                        HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char szBuff[1024];
	char achUrl[1024];
	char LogBuff[LOGBUFFSIZE]="";
	DWORD dwBuffSize=1024;
	DWORD return_rslt;
	pubcookie_dir_rec* p;
	time_t ltime;

	// pFC->pFilterContext = pbc_malloc(p, sizeof(pubcookie_dir_rec)); 
	/* Slower but safer to let IIS handle this malloc */
	pFC->pFilterContext = pFC->AllocMem(pFC,sizeof(pubcookie_dir_rec),0);



	if (!pFC->pFilterContext) {
		syslog(LOG_ERR,"[PBC_OnPreprocHeaders] Error allocating memory");
		return SF_STATUS_REQ_ERROR;
	}
	p = (pubcookie_dir_rec *)pFC->pFilterContext;
	
	memset(p,0,sizeof(pubcookie_dir_rec));

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

	time(&ltime);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "INSTANCE_ID",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Instance ID    : %s\n",szBuff);
	strncpy(p->instance_id, szBuff, MAX_INSTANCE_ID);

	//Check for logging sources and create if needed

	_snprintf (szBuff,1024,"Pubcookie-%s",p->instance_id);
	if (!logsource_exists(p, szBuff)) {
		create_source(p, szBuff);
	}
	if (!logsource_exists(p, "PubCookie")) {
		create_source(p, "PubCookie");
	}

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable (pFC,
      "SERVER_NAME",szBuff,&dwBuffSize);
	AddToLog(LogBuff,"  Server Name    : %s\n",szBuff);
	strncpy((char *)p->server_hostname, szBuff, PBC_APPSRV_ID_LEN);
	strncpy(p->appsrvid, szBuff, PBC_APPSRV_ID_LEN);   // Use SERVER_NAME for appsrvid

	filterlog(p, LOG_INFO,"\n %s \n PBC_OnPreprocHeaders\n",ctime(&ltime));
	/* Have to use szBuff here since p->strbuff in PBC_KEY_DIR will be overwritten with the filterlog call*/
	snprintf(szBuff,1024,"\n Using crypt key: %s\\%s",PBC_KEY_DIR,p->server_hostname);
	filterlog(p, LOG_INFO, szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "REMOTE_HOST",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Remote_Host    : %s\n",szBuff);
	strcpy(p->remote_host,szBuff);

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
	strcpy(p->appsrv_port,szBuff);
	// Force port 80 or 443(ssl) to null
	if ( strcmp(p->appsrv_port, "80") == 0 ||
	 	 strcmp(p->appsrv_port,"443") == 0    )
		strcpy(p->appsrv_port,"");

//	szBuff[0]= NULL; dwBuffSize=1024;
//	pFC->GetServerVariable(pFC,"QUERY_STRING",
//							szBuff, &dwBuffSize);
//	AddToLog(LogBuff,"  Server QUERY_STRING: %s\n",szBuff);

//	szBuff[0]= NULL; dwBuffSize=1024;
//	pHeaderInfo->GetHeader(pFC,"QUERY_STRING:",
//							szBuff, &dwBuffSize);
//	AddToLog(LogBuff,"  Header QUERY_STRING: %s\n",szBuff);
//	strcpy(p->args,szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"HTTP_HOST",
							szBuff, &dwBuffSize);
	AddToLog(LogBuff,"  Server HTTP_HOST  : %s\n",szBuff);

	return_rslt = SF_STATUS_REQ_NEXT_NOTIFICATION;
	p->pszUser[0] = NULL;    // For OnAuth

	filterlog(p, LOG_INFO, LogBuff);
	
   // Begin Pubcookie logic

	if ( Pubcookie_User(pFC,pHeaderInfo) == OK ) //OK - means continue, DECLINED - means serve page/exit filter
//		if ( Pubcookie_Auth(pFC) == OK )
			if ( Pubcookie_Typer(pFC,pHeaderInfo) == OK )
				switch (p->handler)
				{
				case PBC_BAD_AUTH:
				case PBC_FORCE_REAUTH:
				case PBC_BAD_APPID: // Lets try again
					Auth_Failed(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;

				case PBC_BAD_USER:
				case PBC_BAD_GRANTING_CERT:
				case PBC_BAD_SESSION_CERT:
				case PBC_BAD_VERSION:
				case PBC_BAD_SERVERID:
				case PBC_GRANTING_TIMEOUT:
				case PBC_BAD_CRYPT_KEY:
					Bad_User(pFC);
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;

				case PBC_BAD_PORT:      // Redirected to https
				case PBC_LOGOUT_REDIR:   // Redirected to logout server
					return_rslt = SF_STATUS_REQ_FINISHED;
					break;

				default:
					filterlog(p, LOG_ERR,"[PBC_OnPreprocHeaders] Unexpected p->handler value = %d",
						p->handler);
					return_rslt = SF_STATUS_REQ_ERROR;
					break;
				}
//			else
			//	Hide_Cookies(pFC,pHeaderInfo);
//		else
//			Hide_Cookies(pFC,pHeaderInfo);
	else
		Hide_Cookies(pFC,pHeaderInfo);

	filterlog(p, LOG_DEBUG," OnPreprocHeaders returned x%X\n",return_rslt);
	
	return return_rslt;

} /* OnPreprocHeaders */


DWORD OnUrlMap (HTTP_FILTER_CONTEXT* pFC, 
			    HTTP_FILTER_URL_MAP* pUrlMapInfo)
{
	char LogBuff[LOGBUFFSIZE]="";
	pubcookie_dir_rec* p;
	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( p ) {
		AddToLog(LogBuff,"PBC_OnUrlMap (%s)\n",p->remote_host);
	}else {
		AddToLog(LogBuff,"PBC_OnUrlMap\n");
	}

	AddToLog(LogBuff,"  PhysicalPath: %s\n",pUrlMapInfo->pszPhysicalPath);

	filterlog(p, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

} /* OnUrlMap */


DWORD OnAuthentication (HTTP_FILTER_CONTEXT* pFC,
                        HTTP_FILTER_AUTHENT* pAuthInfo)
{
	pubcookie_dir_rec* p;
	char LogBuff[LOGBUFFSIZE]="";
	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( p ) {
		AddToLog(LogBuff,"PBC_OnAuthentication (%s)\n",p->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnAuthentication\n");
	}

	AddToLog(LogBuff,"  Old UserName: %s\n",pAuthInfo->pszUser);
//	AddToLog(LogBuff,"  Old Password: %s\n",pAuthInfo->pszPassword);

	if ( p )
	if ( strlen(p->pszUser) > 0 && p->legacy) {
		// Give the mapped user/password back to the server
		strcpy(pAuthInfo->pszUser    , p->pszUser);
		strcpy(pAuthInfo->pszPassword, p->pszPassword);

		AddToLog(LogBuff,"  New UserName : %s\n",pAuthInfo->pszUser);
		AddToLog(LogBuff,"  New PW length: %d\n",strlen(pAuthInfo->pszPassword));
	}
	filterlog(p, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnAuthentication */


DWORD OnAccessDenied (HTTP_FILTER_CONTEXT* pFC, 
					  HTTP_FILTER_ACCESS_DENIED* pDenyInfo)
{
	pubcookie_dir_rec* p;
	char LogBuff[LOGBUFFSIZE]="";

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( p ) {
		AddToLog(LogBuff,"PBC_OnAccessDenied (%s)\n",p->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnAccessDenied\n");
	}

	AddToLog(LogBuff,"  URL   : %s\n",pDenyInfo->pszURL);
	AddToLog(LogBuff,"  PATH  : %s\n",pDenyInfo->pszPhysicalPath);
	AddToLog(LogBuff,"  Reason: x%x\n",pDenyInfo->dwReason);

	filterlog(p, LOG_INFO, LogBuff);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnAccessDenied */


DWORD OnSendResponse (HTTP_FILTER_CONTEXT* pFC,
                      HTTP_FILTER_SEND_RESPONSE* pResponseInfo)
{
	pubcookie_dir_rec* p;
	char LogBuff[LOGBUFFSIZE]="";

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( p ) {
		AddToLog(LogBuff,"PBC_OnSendResponse (%s)\n",p->remote_host);
	} 

	AddToLog(LogBuff,"  HttpStatus: %d\n",pResponseInfo->HttpStatus);

	if ( p ) {
		filterlog(p, LOG_INFO, LogBuff);
    }
	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnSendResponse */ 


DWORD OnSendRawData (HTTP_FILTER_CONTEXT* pFC,
                     HTTP_FILTER_RAW_DATA* pRawDataInfo)
{
	pubcookie_dir_rec* p;
	char LogBuff[LOGBUFFSIZE]="";

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( p ) {
		AddToLog(LogBuff,"PBC_OnSendRawData (%s)\n",p->remote_host);
	} else {
		AddToLog(LogBuff,"PBC_OnSendRawData\n");
	}

	AddToLog(LogBuff,"  Sending(%d): \n%.*s\n",
		pRawDataInfo->cbInData,pRawDataInfo->cbInData,pRawDataInfo->pvInData);

	syslog(LOG_INFO, LogBuff);  

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnSendRawData */


DWORD OnEndOfRequest (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* p;
	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( p ) {
		filterlog(p, LOG_INFO,"PBC_OnEndOfRequest (%s)\n",p->remote_host);
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
	//char LogBuff[LOGBUFFSIZE]="";  Logging here is too problematic with IIS 6 threads being terminated from outside
	DWORD dwBuffSize,dwReserved=NULL;
	pubcookie_dir_rec* p;
	char *pszNewClient;

	p = (pubcookie_dir_rec *)pFC->pFilterContext;

	//AddToLog(LogBuff,"PBC_OnLog\n");

	szBuff[0]= NULL; dwBuffSize=1024;

	pFC->GetServerVariable(pFC, "INSTANCE_ID",
							szBuff, &dwBuffSize);
	//AddToLog(LogBuff,"  Instance ID   : %s\n",szBuff);

	if ( p ) {
		if (strlen(p->user) > 0) {
			dwBuffSize=1024;
			
			pszNewClient = (char *)pFC->AllocMem(pFC,dwBuffSize,0);		
			strncpy(pszNewClient,(PBC_CLIENT_LOG_FMT), dwBuffSize);
			ReplaceToken("%w",pLogInfo->pszClientUserName,pszNewClient, dwBuffSize);
			ReplaceToken("%p",p->user, pszNewClient, dwBuffSize);
			//AddToLog(LogBuff,"  Modified user : %s\n",pszNewClient);
			pLogInfo->pszClientUserName = pszNewClient;
		}
	}
	/* AddToLog(LogBuff,"  ClientHostName: %s\n",pLogInfo->pszClientHostName);
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

	filterlog(p, LOG_INFO, LogBuff);
	*/

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnLog */


DWORD OnEndOfNetSession (HTTP_FILTER_CONTEXT* pFC)
{
			

	return SF_STATUS_REQ_NEXT_NOTIFICATION;


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

BOOL WINAPI TerminateExtension(DWORD dwFlags)
{
	syslog(LOG_INFO, "\nPBC_TerminateExtension Called \n");

	return TRUE;
}

BOOL SendHttpHeaders(EXTENSION_CONTROL_BLOCK *pECB, LPCSTR pszStatus, LPCSTR pszHeaders)
{
	HSE_SEND_HEADER_EX_INFO header_ex_info;

	header_ex_info.pszStatus = pszStatus;
	header_ex_info.pszHeader = pszHeaders;
	header_ex_info.cchStatus = strlen(pszStatus);
	header_ex_info.cchHeader = strlen(pszHeaders);
	header_ex_info.fKeepConn = FALSE;

	return pECB->ServerSupportFunction(pECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER_EX, &header_ex_info, NULL, NULL);
}

BOOL WINAPI GetExtensionVersion(OUT HSE_VERSION_INFO *pVer)
{
	// set version to httpext.h version constants
	
	pVer->dwExtensionVersion = MAKELONG(HSE_VERSION_MINOR, HSE_VERSION_MAJOR);

	lstrcpyn((LPSTR) pVer->lpszExtensionDesc, "Pubcookie Form Extension", HSE_MAX_EXT_DLL_NAME_LEN);

	return TRUE;
}       

void output_error_page(EXTENSION_CONTROL_BLOCK *pECB) {

   // syslog(LOG_WARN,"Extension sent error page");  //  Access issues in IIS6

   SendHttpHeaders(pECB, "200 OK", "Content-type: text/html\r\n\r\n");

   //output page
   WriteString(pECB,"<HTML>\r\n");
   WriteString(pECB,"<HEAD>\r\n");
   WriteString(pECB,"<title>A problem has occurred</title>\r\n");
   WriteString(pECB,"</HEAD>\r\n");
   WriteString(pECB,"<BODY bgcolor=\"#ffffff\">\r\n");
   WriteString(pECB,"<h1>A problem has occurred or you have reached this page in error</H1>\r\n");
   WriteString(pECB,"</BODY>\r\n");
   WriteString(pECB,"</HTML>\r\n");
}

void output_debug_page(EXTENSION_CONTROL_BLOCK *pECB, const char *msg) {
   char sztmpstr[MAX_BUFFER];

   SendHttpHeaders(pECB, "200 OK", "Content-type: text/html\r\n\r\n");

   //output page
   WriteString(pECB,"<HTML>\r\n");
   WriteString(pECB,"<HEAD>\r\n");
   WriteString(pECB,"<title>Debug Message</title>\r\n");
   WriteString(pECB,"</HEAD>\r\n");
   WriteString(pECB,"<BODY bgcolor=\"#ffffff\">\r\n");
   snprintf(sztmpstr,MAX_BUFFER,"<h1>%s</H1>\r\n",msg);
   WriteString(pECB,sztmpstr);
   WriteString(pECB,"</BODY>\r\n");
   WriteString(pECB,"</HTML>\r\n");
}


/* Requests from an application will have a granting request
   and possibly post data.  Relay these to the login server. 
   
   This function is obsolete.  Filter will initiate POST 
   for granting request */
   
void relay_granting_request(EXTENSION_CONTROL_BLOCK *pECB, pubcookie_dir_rec *p, char *greq)
{
   char *post=NULL;
   char httpheader[START_COOKIE_SIZE+256];
   char sztmpstr[MAX_BUFFER];
   DWORD dwBufferSize = sizeof sztmpstr;

   // Send HTTP headers and clear granting reqest cookie
   sprintf(httpheader, "Set-Cookie: %s=%s; domain=%s; path=/; expires=%s; secure\r\nContent-type: text/html\r\n\r\n", 
			PBC_G_REQ_COOKIENAME,
			PBC_CLEAR_COOKIE,
			p->appsrvid, 
			EARLIEST_EVER);

   SendHttpHeaders(pECB, "200 OK", httpheader);
   WriteString(pECB,"<html>\r\n");
   WriteString(pECB,"<body onLoad=\"document.relay.submit()\">\r\n");

   snprintf(sztmpstr,MAX_BUFFER,"<form method=post action=\"%s\" name=relay>\r\n\r\n",p->Login_URI);
   WriteString(pECB,sztmpstr);
   
   snprintf(sztmpstr,MAX_BUFFER,"<input type=hidden name=pubcookie_g_req value=\"%s\">\r\n",greq);
   WriteString(pECB,sztmpstr);
   
  // snprintf(sztmpstr,MAX_BUFFER,"<input type=hidden name=post_stuff value=\"%s\">\r\n",post);
  // WriteString(pECB,sztmpstr);
   
   snprintf(sztmpstr,MAX_BUFFER,"<input type=hidden name=relay_url value=\"%s\">\r\n\r\n", p->Relay_URI);
   
   WriteString(pECB,sztmpstr);
   WriteString(pECB,"<noscript>\r\n");
   WriteString(pECB,"<p align=center>You do not have Javascript turned on,\r\n");
   WriteString(pECB,"please click the button to continue.\r\n");
   WriteString(pECB,"<p align=center> <input type=submit name=go value=\"Continue\">\r\n");
   WriteString(pECB,"</noscript>\r\n\r\n");
   WriteString(pECB,"</form>\r\n");
   WriteString(pECB,"</body>\r\n");
   WriteString(pECB,"</html>\r\n");
}


/* Requests from the login server will have a granting reply
   and post data.  Relay these to the application. */


static int need_area(char *in)
{
  for (; *in; in++) {
      if (*in=='"') return (1);
      if (*in=='\n') return (1);
      if (*in=='\r') return (1);
  }
  return (0);
}

/* Return value of arg from http querystring.  If valuesize is zero, allocate space for value */

BOOL getqueryarg (const char* querystr, char* value, const char* arg, int valuesize) {

	char *searchstr, *pos1, *pos2;

	size_t mallocsize = sizeof(char)*(strlen(arg)+2);
	if (!(searchstr = (char *)malloc(mallocsize))) {
		return FALSE;
    }
	strcpy(searchstr,arg);
	strcat(searchstr,"=");
	
	if (valuesize == 0) {
		mallocsize = sizeof(char)*2;
		if (!(value = (char *)malloc(mallocsize))) {
			return FALSE;
		}
	}
	if (pos1 = strstr(querystr, searchstr)) {
		pos1 += strlen(searchstr);
		if (!(pos2 = strchr(pos1,'&'))) {
			pos2 = pos1+strlen(pos1);
		}
		if (valuesize == 0) {
			valuesize = pos2-pos1+1;
			mallocsize =  sizeof(char) * valuesize;
			if (!(value = (char *)malloc(mallocsize))) {
				return FALSE;
			}
		}
		if ( pos2-pos1 < valuesize ) {
			strncpy(value,pos1,pos2-pos1);
		} else {
			strcpy(value,"");
			return FALSE;
		}
	} else {
		strcpy(value,"");
		return FALSE;
	}

	free(searchstr);
	return TRUE;
}

void relay_granting_reply(EXTENSION_CONTROL_BLOCK *pECB, pubcookie_dir_rec *p, char *grpl, char *redirect_url)
{ 
   char httpheader[START_COOKIE_SIZE+1024];
   char sztmpstr[MAX_BUFFER];

   // Send HTTP headers and set granting cookie

   // syslog(LOG_INFO,"Extension relaying cookie %s\n   domain=%s;\n   path=/;\n   secure;\n",PBC_G_COOKIENAME,p->Enterprise_Domain);
   // Access issues in 6.0

   snprintf(httpheader, START_COOKIE_SIZE+1024, "Set-Cookie: %s=%s; domain=%s; path=/; secure\r\nContent-type: text/html\r\n\r\n", 
			PBC_G_COOKIENAME,
			grpl,
			p->appsrvid); 

   SendHttpHeaders(pECB, "200 OK", httpheader);

   //output page
   WriteString(pECB,"<HTML>\r\n");
   WriteString(pECB,"<HEAD>\r\n");
   snprintf(sztmpstr,MAX_BUFFER,"<meta http-equiv=\"Refresh\" content=\"0;URL=%s\"\r\n>",redirect_url);
   WriteString(pECB,sztmpstr);
   WriteString(pECB,"</HEAD>\r\n");
   WriteString(pECB,"<BODY>\r\n");
   WriteString(pECB,"</BODY>\r\n");
   WriteString(pECB,"</HTML>\r\n");
}


/* Logout requests from an application will have a the
   logout action variable.  Relay to the login server. 
   
   Function is obsolete
   Filter will initate logout directly*/
  
void relay_logout_request(EXTENSION_CONTROL_BLOCK *pECB, pubcookie_dir_rec *p, char *act, const char *qs)
{
   char *a1=NULL, *a2=NULL;
   char *furl;
   size_t l;

   char *post=NULL;
   char httpheader[START_COOKIE_SIZE+256];
   char sztmpstr[MAX_BUFFER];
   DWORD dwBufferSize = sizeof sztmpstr;

   // Send HTTP headers and clear granting reqest cookie
   sprintf(httpheader, "Set-Cookie: %s=%s; domain=%s; path=/; expires=%s; secure\r\nContent-type: text/html\r\n\r\n", 
			PBC_G_REQ_COOKIENAME,
			PBC_CLEAR_COOKIE,
			p->appsrvid, 
			EARLIEST_EVER);

   SendHttpHeaders(pECB, "200 OK", httpheader);


   // Build the redirection 
   if (!getqueryarg(qs,a1,"one",0)) {
		a1 = strdup("");
   }
   if (!getqueryarg(qs,a2,"two",0)) {
		a2 = strdup("");
   }

   l = strlen(p->Login_URI) + 
         strlen(PBC_GETVAR_LOGOUT_ACTION) + strlen(act) +
         strlen(a1) + strlen(a2) + 32;
   furl = (char*) malloc(l);
   snprintf(furl,l, "%s?%s=%s&one=%s&two=%s", p->Login_URI,
           PBC_GETVAR_LOGOUT_ACTION, act, a1, a2);

   //output page
   WriteString(pECB,"<HTML>\r\n");
   WriteString(pECB,"<HEAD>\r\n");
   snprintf(sztmpstr,MAX_BUFFER,"<meta http-equiv=\"Refresh\" content=\"0;URL=%s\"\r\n>",furl);
   WriteString(pECB,sztmpstr);
   WriteString(pECB,"</HEAD>\r\n");
   WriteString(pECB,"<BODY>\r\n");
   WriteString(pECB,"</BODY>\r\n");
   WriteString(pECB,"</HTML>\r\n");

   free(furl);
   free(a1);
   free(a2);
}

DWORD WINAPI HttpExtensionProc(IN EXTENSION_CONTROL_BLOCK *pECB)
{
  char *cookie=NULL, *val=NULL, *postdata=NULL, *redirect_url=NULL;
  char *host, *port, *uri, *qs;
  char *uport;
  int ishttps;
  char szBuffer[MAX_BUFFER];
  DWORD dwBufferSize;
  size_t ts;
  DWORD retcode=HSE_STATUS_SUCCESS;
  HKEYLIST hKeyList, hKeyFound;

 //Sleep(20000);  //debug
  pubcookie_dir_rec *p = (pubcookie_dir_rec *)malloc(sizeof(pubcookie_dir_rec));
  memset(p,0,sizeof(pubcookie_dir_rec));

  dwBufferSize = sizeof szBuffer;
  if ((pECB->GetServerVariable(pECB->ConnID, "QUERY_STRING", szBuffer, &dwBufferSize))) {
	  qs = strdup(szBuffer);
  } else {
	  qs = "";
  }

  getqueryarg(qs, p->appsrvid,"appsrvid",1024);

  // syslog(LOG_ERR,"p->Login_URI = %s : strlen = %d",p->Login_URI,strlen(p->Login_URI)); 

  if (strlen(p->appsrvid) < 1) {
	 output_error_page(pECB);
     return HSE_STATUS_ERROR;
  }

  libpbc_config_init(p, NULL, "relay");

  /* figure out relay uri */

  dwBufferSize = sizeof szBuffer;
  if (pECB->GetServerVariable(pECB->ConnID, "SERVER_NAME", szBuffer, &dwBufferSize)) {
	  host = strdup(szBuffer);
  } else {
	  host = strdup("nohost");
  }

  dwBufferSize = sizeof szBuffer;
  if (pECB->GetServerVariable(pECB->ConnID, "URL", szBuffer, &dwBufferSize)) {
	  uri = strdup(szBuffer);
  } else {
	  uri = strdup("/");
  }

  dwBufferSize = sizeof szBuffer;
  if (pECB->GetServerVariable(pECB->ConnID, "SERVER_PORT", szBuffer, &dwBufferSize)) {
	  port=strdup(szBuffer);
  } else {
	  port=NULL;
  }

  dwBufferSize = sizeof szBuffer;
  if (pECB->GetServerVariable(pECB->ConnID, "SERVER_PORT_SECURE", szBuffer, &dwBufferSize)) {
	  if (strcmp(szBuffer,"0")) ishttps = 1;
		else ishttps = 0;
  } else {
	  ishttps = 0;
  }

  if (port && strcmp(port,ishttps?"443":"80")) {
     uport = (char*) malloc(2+strlen(port));
     sprintf(uport,":%s", port);
  } else uport = strdup("");

  ts = 24 + strlen(host) + strlen(uport) + strlen(uri) + strlen(qs);
  p->Relay_URI = (char*) malloc(ts);
  snprintf(p->Relay_URI,ts,"http%c://%s%s%s%s%s",
           ishttps?'s':'\0', host, uport, uri,*qs?"?":"", qs); 

  /* A logout request to the login server will have a
     logout action variable */

  if (getqueryarg(qs,val,PBC_GETVAR_LOGOUT_ACTION,0)) {
      relay_logout_request(pECB, p, val, qs);
      free(val);
  } else {
    /* A login reply to the application will have a granting
     cookie in posted form data */
     hKeyList = GetKeyList(pECB);

     if (hKeyFound = FindKey(hKeyList,PBC_G_COOKIENAME)) {
		 postdata = (char *)GetKeyBuffer(hKeyFound);
		 if (hKeyFound = FindKey(hKeyList,"redirect_url")) {
		     redirect_url = (char *)GetKeyBuffer(hKeyFound);
		 }
         relay_granting_reply(pECB, p, postdata, redirect_url); 
    } else  

      /* A login request from an application will have a granting 
       request cookie */
       if (cookie= Get_Ext_Cookie(pECB, p, PBC_G_REQ_COOKIENAME)) {
           relay_granting_request(pECB, p, cookie);

          /* Otherwise this is an invalid request */

    } else {
       output_error_page(pECB);
       retcode = HSE_STATUS_ERROR;
    }
   FreeKeyList(hKeyList);
  }

  free(uport);
  free(p);
  return retcode;
}


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
			
			// Initialize Pubcookie Stuff - and Set Debug Trace Flags
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


