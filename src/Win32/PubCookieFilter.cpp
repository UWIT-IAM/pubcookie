/////////////////////////////////////////////////
//
//  Copyright 1999-2001, University of Washington. All rights reserved.
//
//  PubcookieFilter.cpp


#define COOKIE_PATH

#include <windows.h>
#include <stdio.h>
#include <direct.h>       // For mkdir
#include <time.h>
#include <process.h>
// #include <shfolder.h>  // For System Path, in Platform SDK
#include <httpfilt.h>

extern "C" 
{
#include <pem.h>
#include "../pubcookie.h"
#include "../libpubcookie.h"
#include "../pbc_config.h"
#include "../pbc_version.h"
#include "../pbc_myconfig.h"
#include "PubCookieFilter.h"
}



int	Debug_Trace=0;
FILE *debugFile=NULL;


BOOL Open_Debug_Trace ();

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


VOID ReportPFEvent(PTSTR string1,PTSTR string2,PTSTR string3,PTSTR string4,
               WORD eventType, WORD eventID) 
{
   HANDLE hEvent;
   PTSTR pszaStrings[4];
   WORD cStrings;

   // Check to see how many strings were passed
   cStrings = 0;
   if ((pszaStrings[0] = string1) && (string1[0])) cStrings++;
   if ((pszaStrings[1] = string2) && (string2[0])) cStrings++;
   if ((pszaStrings[2] = string3) && (string3[0])) cStrings++;
   if ((pszaStrings[3] = string4) && (string4[0])) cStrings++;
   if (cStrings == 0)
      return;
   
   hEvent = RegisterEventSource(NULL,"W3SVC");
   if (hEvent) 
   {
      ReportEvent(hEvent, eventType, NULL, eventID, NULL, cStrings, NULL,                  
                (const char **)pszaStrings, NULL);                   
      DeregisterEventSource(hEvent);
   }

   DebugMsg((DEST,"\n*** %s\n\n",string2));
}

VOID Close_Debug_Trace ()
{
	time_t ltime;

	DebugMsg((DEST,"Close_Debug_Trace\n"));  //debug
	if ( debugFile ) {

		time(&ltime);
		DebugMsg(( DEST, "\n  %s\n\n", ctime(&ltime)));
		DebugMsg(( DEST, "  PubcookieFilter Stats:\n"));
		DebugMsg(( DEST, "    Total_Requests     = %d\n",Total_Requests));
		DebugMsg(( DEST, "    Max_Url_Length     = %d\n",Max_Url_Length));
		DebugMsg(( DEST, "    Max_Query_String   = %d\n",Max_Query_String));
		DebugMsg(( DEST, "    Max_Content_Length = %d\n",Max_Content_Length));
		DebugMsg(( DEST, "    Max_Cookie_Size    = %d\n",Max_Cookie_Size));
		DebugMsg(( DEST, "    Max_Bytes_Sent     = %d\n",Max_Bytes_Sent));
		DebugMsg(( DEST, "    Max_Bytes_Recvd    = %d\n",Max_Bytes_Recvd));

		fclose(debugFile);

		debugFile = NULL;

		Total_Requests     = 0;
		Max_Url_Length     = 0;
		Max_Query_String   = 0;
		Max_Content_Length = 0;
		Max_Cookie_Size    = 0;
		Max_Bytes_Sent     = 0;
		Max_Bytes_Recvd    = 0;
	}
}

BOOL Open_Debug_Trace ()
{
    char szName[256], szBuff[1024];
	time_t ltime;
	struct tm *today;

	DebugMsg((DEST,"Open_Debug_Trace\n"));  //debug


	time(&ltime);
	today = localtime(&ltime);
	strftime(Trace_Date,64,"%Y%m%d\0",today);
	sprintf(szBuff,"%s%s",Debug_Dir,Instance);
	sprintf(szName,"%s%s\\%s.log",Debug_Dir,Instance,Trace_Date);
//	sprintf(szName,"%s%d.log",DEBUG_FILE,HIWORD(hinstDll));

	// Directory must exist else open will fail

	mkdir(szBuff);

	// output stats if file already open

	Close_Debug_Trace ();

	debugFile = fopen(szName, "a");

	if ( !debugFile ) {
		sprintf(szBuff,"[Open_Debug_Trace] Failed to open trace file %s",szName);
		ReportPFEvent("[PubcookieFilter]",szBuff,
			"","",EVENTLOG_ERROR_TYPE,3);
	}
		
	DebugMsg((DEST, "\n**********************************************************************\n %s\n\n Opening Debug File %s\n\n",
		ctime(&ltime),szName));

	if ( debugFile ) 
		return TRUE;
	else
		return FALSE;
}

VOID Clear_Cookie(HTTP_FILTER_CONTEXT* pFC, char* cookie_name, char* cookie_domain, char* cookie_path)
{

	char new_cookie[START_COOKIE_SIZE];

	DebugMsg((DEST,"Clear_Cookie\n"));  //debug


	sprintf(new_cookie, "Set-Cookie: %s=clear; domain=%s; path=%s; expires=%s; secure\r\n", 
			cookie_name, 
			cookie_domain, 
			cookie_path,
			"Fri, 01-Jan-1970 00:00:01 GMT");

	
		DebugMsg((DEST,"  AddResponseHeaders2= \n%s",new_cookie));
	
		pFC->AddResponseHeaders(pFC,new_cookie,0);

		DebugMsg((DEST,"  Cleared Cookie %s\n",cookie_name));
}

VOID Read_Default_Reg_Settings()
{
	int rslt;
	HKEY hKey;
	char key [1024];
	DWORD dwRead;

	DebugMsg((DEST,"Read_Default_Reg_Settings\n"));  //debug

	// Read Registry keys for app defaults

	Debug_Trace = 0;
	strcpy(Debug_Dir,SystemRoot); strcat(Debug_Dir,DEBUG_DIR);
	strcpy(scfg.NTUserId,"");
	strcpy(scfg.Password,"");
	scfg.inact_exp = PBC_DEFAULT_INACT_EXPIRE;
	scfg.hard_exp  = PBC_DEFAULT_HARD_EXPIRE;
	strcpy(scfg.force_reauth,PBC_NO_FORCE_REAUTH);
	scfg.session_reauth = 0;
	strcpy(scfg.logout_dir,LOGOUT);
	strcpy(scfg.logout_redir_dir,LOGOUT_REDIR);
	scfg.AuthType  = PBC_CREDS_NONE;
	Ignore_Poll = 0;
	sprintf(Web_Login,"https://%s/%s",PBC_LOGIN_HOST,PBC_LOGIN_URI);

	strcpy(Enterprise_Domain,PBC_ENTRPRS_DOMAIN);
	strcpy(Error_Page,"");

	strcpy (key,PUBKEY);
	strcat (key,"Default");

	if (rslt = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	                        key,0,KEY_READ,&hKey) == ERROR_SUCCESS)
	{
		dwRead = sizeof (Debug_Trace);
		if (RegQueryValueEx (hKey, "Debug_Trace",
							 NULL, NULL, (LPBYTE) &Debug_Trace, &dwRead) != ERROR_SUCCESS)
		{
		} 
		dwRead = sizeof (Debug_Dir);
		if (RegQueryValueEx (hKey, "Debug_Dir",
							 NULL, NULL, (LPBYTE) Debug_Dir, &dwRead) != ERROR_SUCCESS)
		{
		}
		dwRead = sizeof (scfg.NTUserId);
		if (RegQueryValueEx (hKey, "NTUserId",
							 NULL, NULL, (LPBYTE) scfg.NTUserId, &dwRead) != ERROR_SUCCESS)
		{		    
		} 
		dwRead = sizeof (scfg.Password);
		if (RegQueryValueEx (hKey, "Password",
							 NULL, NULL, (LPBYTE) scfg.Password, &dwRead) != ERROR_SUCCESS)
		{     
		}
		dwRead = sizeof (scfg.inact_exp);
		if (RegQueryValueEx (hKey, "Inactive_Timeout",
							 NULL, NULL, (LPBYTE) &scfg.inact_exp, &dwRead) != ERROR_SUCCESS)
		{      
		} 
		dwRead = sizeof (scfg.hard_exp);
		if (RegQueryValueEx (hKey, "Hard_Timeout",
							 NULL, NULL, (LPBYTE) &scfg.hard_exp, &dwRead) != ERROR_SUCCESS)
		{     
		}
		dwRead = sizeof (scfg.force_reauth);
		if (RegQueryValueEx (hKey, "Force_Reauth",
							 NULL, NULL, (LPBYTE) scfg.force_reauth, &dwRead) != ERROR_SUCCESS)
		{     
		}

		dwRead = sizeof (scfg.session_reauth);
		if (RegQueryValueEx (hKey, "Session_Reauth",
							 NULL, NULL, (LPBYTE) &scfg.session_reauth, &dwRead) != ERROR_SUCCESS)
		{     
		}

/*		dwRead = sizeof (scfg.logout);
		if (RegQueryValueEx (hKey, "Logout",
							 NULL, NULL, (LPBYTE) &scfg.logout, &dwRead) != ERROR_SUCCESS)
		{     
		}*/
		dwRead = sizeof (scfg.logout_dir);
		if (RegQueryValueEx (hKey, "Logout_Dir",
							 NULL, NULL, (LPBYTE) &scfg.logout_dir, &dwRead) != ERROR_SUCCESS)
		{     
		}
		dwRead = sizeof (scfg.logout_redir_dir);
		if (RegQueryValueEx (hKey, "Logout_Redir_Dir",
							 NULL, NULL, (LPBYTE) &scfg.logout_redir_dir, &dwRead) != ERROR_SUCCESS)
		{     
		}

		dwRead = sizeof (key); key[0] = NULL;
		if (RegQueryValueEx (hKey, "AuthType",
							 NULL, NULL, (LPBYTE) key, &dwRead) != ERROR_SUCCESS)
		{     
		} else {
			if ( stricmp(key,NETID) == 0 ) 
				scfg.AuthType = PBC_CREDS_CRED1;
			else
			if ( stricmp(key,SECURID) == 0 ) 
				scfg.AuthType = PBC_CREDS_CRED3;
			else
				scfg.AuthType = PBC_CREDS_NONE;
		}
		dwRead = sizeof (Ignore_Poll);
		if (RegQueryValueEx (hKey, "Ignore_Poll",
							 NULL, NULL, (LPBYTE) &Ignore_Poll, &dwRead) != ERROR_SUCCESS)
		{     
		}
		dwRead = sizeof (Web_Login);
		if (RegQueryValueEx (hKey, "Web_Login",
							 NULL, NULL, (LPBYTE) Web_Login, &dwRead) != ERROR_SUCCESS)
		{
		}
		dwRead = sizeof (Enterprise_Domain);
		if (RegQueryValueEx (hKey, "Enterprise_Domain",
							 NULL, NULL, (LPBYTE) Enterprise_Domain, &dwRead) != ERROR_SUCCESS)
		{
		}
		dwRead = sizeof (Error_Page);
		if (RegQueryValueEx (hKey, "Error_Page",
							 NULL, NULL, (LPBYTE) Error_Page, &dwRead) != ERROR_SUCCESS)
		{
		}
		
	}
	RegCloseKey (hKey);

	if (Debug_Trace && !debugFile) {
		Open_Debug_Trace ();
	} else
	if (!Debug_Trace && debugFile) {
		Debug_Trace = 1;
		Close_Debug_Trace ();
		Debug_Trace = 0;
	}

	DebugMsg((DEST,"Pubcookie_Init\n"));

	DebugMsg((DEST,"  %s\n",Pubcookie_Version));

	DebugMsg((DEST,"  Defaults are: Debug_Trace      : %d\n" ,Debug_Trace));
	DebugMsg((DEST,"                Debug_Dir        : %s\n" ,Debug_Dir));
	DebugMsg((DEST,"                NtUserId         : %s\n" ,scfg.NTUserId));
	DebugMsg((DEST,"                PW Length        : %d\n" ,strlen(scfg.Password)));
	DebugMsg((DEST,"                Inact_Exp        : %d\n" ,scfg.inact_exp));
	DebugMsg((DEST,"                Hard_Exp         : %d\n" ,scfg.hard_exp));
	DebugMsg((DEST,"                Force_Reauth     : %s\n" ,scfg.force_reauth));
	DebugMsg((DEST,"                Session_Reauth   : %1d\n" ,scfg.session_reauth));
//	DebugMsg((DEST,"                Logout           : %1d\n" ,scfg.logout));
	DebugMsg((DEST,"                Logout_Dir       : %s\n" ,scfg.logout_dir));
	DebugMsg((DEST,"                Logout_Redir_dir : %s\n" ,scfg.logout_redir_dir));
	DebugMsg((DEST,"                AuthType         : %c\n" ,scfg.AuthType));
	DebugMsg((DEST,"                Ignore_Poll      : %d\n" ,Ignore_Poll));
	DebugMsg((DEST,"                Web_Login        : %s\n" ,Web_Login));
	DebugMsg((DEST,"                Enterprise_Domain: %s\n" ,Enterprise_Domain));

}

BOOL Pubcookie_Init () 
{
    char szBuff[1024];
	char szName[1024];
    DWORD dwBuffSize = 1024;
	int rslt;
	hostent *hp;

	// Need TCPIP for gethostname stuff
	   
	WSADATA wsaData;

//	DebugMsg(( DEST, " Pubcookie_init\n"));

	DebugMsg((DEST,"Pubcookie_Init\n"));  //debug


	memset(&scfg,0,sizeof(pubcookie_server_rec));

	Total_Requests     = 0;
	Max_Url_Length     = 0;
	Max_Query_String   = 0;
	Max_Content_Length = 0;
	Max_Cookie_Size    = 0;
	Max_Bytes_Sent     = 0;
	Max_Bytes_Recvd    = 0;

	// filter won't run calling routine below for some reason

//	rslt=SHGetFolderPath(NULL,CSIDL_SYSTEM,NULL,0,System_Path);

	rslt = GetEnvironmentVariable ("windir",SystemRoot,256);

//	DebugMsg((DEST,"  SystemRoot    = %s, rslt = %d\n",SystemRoot,rslt));

	Read_Default_Reg_Settings();

	if (!libpbc_config_init("","")) {
		ReportPFEvent("[PubcookieFilter]","[Pubcookie_Config_Init] Out of memory.",
		"","",EVENTLOG_ERROR_TYPE,3);

 		return FALSE; 
	} 

	if ( rslt = WSAStartup((WORD)0x0101, &wsaData ) ) 
		{
		sprintf(szBuff,"[Pubcookie_Init] Unable to initialize WINSOCK: %d",rslt);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
	    return FALSE;
		}

	InitializeCriticalSection(&Ctx_Plus_CS); 

	// Initialize Pubcookie Stuff

    libpbc_pubcookie_init();

	// HTTP_FILTER_CONTEXT is not available at DllMain time

//	pFC->GetServerVariable (pFC,
//      "SERVER_NAME",szBuff,&dwBufferSize);

	szBuff[0] = NULL;

    if ( rslt = gethostname(szBuff, sizeof(szBuff)) ) {
		sprintf(szBuff,"[Pubcookie_Init] Gethostname failed = %d, LastErr= %d",
				rslt,WSAGetLastError());
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return FALSE;
	}
 
	DebugMsg((DEST,"  gethostname   = %s\n",szBuff));
	
	strcpy((char *)scfg.server_hostname, szBuff);
	
	if ( !(hp = gethostbyname(szBuff)) ) {
		sprintf(szBuff,"[Pubcookie_Init] Gethostbyname failed, LastErr= %d",
				WSAGetLastError());
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return FALSE;
	}

	  DebugMsg((DEST,"  gethostbyname = %s\n",
					hp->h_name));

	// May need to search through aliases if we have local hosts file
	strncpy((char *)scfg.server_hostname, hp->h_name, PBC_APPSRV_ID_LEN);

    strcpy(szName,SystemRoot);  strcat(szName,PBC_CRYPT_KEYFILE);
	scfg.c_stuff                = libpbc_init_crypt (szName);

	if ( !scfg.c_stuff ) {
		sprintf(szBuff,"[Pubcookie_Init] Libpbc_init_crypt failed Keyfile = %s",
				szName);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return FALSE;
	}

	strcpy(szName,SystemRoot);  strcat(szName,PBC_S_KEYFILE);
    scfg.session_sign_ctx_plus  = libpbc_sign_init  (szName);

	if ( !scfg.session_sign_ctx_plus ) {
		sprintf(szBuff,"[Pubcookie_Init] Libpbc_sign_init failed Keyfile = %s",
				szName);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return FALSE;
	}

	strcpy(szName,SystemRoot);  strcat(szName,PBC_S_CERTFILE);
	scfg.session_verf_ctx_plus  = libpbc_verify_init(szName);

	if ( !scfg.session_verf_ctx_plus ) {
		sprintf(szBuff,"[Pubcookie_Init] Libpbc_verify_init failed Certfile = %s",
				szName);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return FALSE;
	}

	strcpy(szName,SystemRoot);  strcat(szName,PBC_G_CERTFILE);
	scfg.granting_verf_ctx_plus = libpbc_verify_init(szName);

	if ( !scfg.granting_verf_ctx_plus ) {
		sprintf(szBuff,"[Pubcookie_Init] Libpbc_verify_init failed Certfile = %s",
				szName);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return FALSE;
	}

	return TRUE;

}  /* Pubcookie_Init */


void Blank_Cookie (HTTP_FILTER_CONTEXT* pFC,
				   HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo,
				   char *name) 
{
	// 'X' out the pubcookie cookies so the web page can't see them.

	DebugMsg((DEST," Blank_Cookie\n")); 

	char cookie_data[MAX_COOKIE_SIZE+1]; 
	char *cookie;
	char *ptr;
	char name_w_eq[256];
	int pos;
	DWORD cbSize, dwError;

	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pHeaderInfo->GetHeader(pFC,"Cookie:",cookie_data,&cbSize)) {
		dwError = GetLastError();
		DebugMsg((DEST," GetHeader[Cookie:] failed = %d (%x), buffer size= %d\n",
			dwError,dwError,cbSize));
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
	DebugMsg((DEST," Hide_Cookies\n"));

	Blank_Cookie(pFC, pHeaderInfo, PBC_S_COOKIENAME);
    Blank_Cookie(pFC, pHeaderInfo, PBC_G_COOKIENAME);

    return OK;

} /* Hide_Cookies */


int Auth_Failed (HTTP_FILTER_CONTEXT* pFC) 
{
	char 			refresh[PBC_1K];
	char 			new_cookie[START_COOKIE_SIZE];
	char 			args[PBC_4K];
	char 			g_req_contents[PBC_4K];
	char 			e_g_req_contents[PBC_4K];
	char			szHeaders[PBC_1K];
	char			szTemp[1024];
	DWORD			dwSize;
	pubcookie_dir_rec* dcfg;

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	DebugMsg((DEST," Auth_Failed\n"));

	/* reset these dippy flags */
	dcfg->failed = 0;

	/* deal with GET args */
	if ( strlen(dcfg->args) > 0 ) {
		if ( strlen(dcfg->args) > sizeof(args) ) {  // ?? does base64 double size ??
			sprintf(szTemp,"[Pubcookie_Init] Invalid Args Length = %d; remote_host: %s",
				strlen(dcfg->args), dcfg->remote_host);
			ReportPFEvent("[PubcookieFilter]",szTemp,
				   "","",EVENTLOG_ERROR_TYPE,3);
			strcpy(args, "");
		} else
			libpbc_base64_encode((unsigned char *)dcfg->args, (unsigned char *)args,
						strlen(dcfg->args));
		}
	else
		strcpy(args, "");

	strcpy(szTemp,dcfg->appsrvid);
	if ( strlen(dcfg->appsrv_port) > 0 ) {
		strcat(szTemp,":");
		strcat(szTemp,dcfg->appsrv_port);
	}

	/* make the granting request */
	sprintf(g_req_contents, 
		"%s=%s&%s=%s&%s=%c&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%1d", 
		PBC_GETVAR_APPSRVID,
		  scfg.server_hostname,   // Need full domain name 
		PBC_GETVAR_APPID,
		  dcfg->appid,
		PBC_GETVAR_CREDS, 
		  dcfg->creds, 
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
		PBC_GETVAR_FR,
		  dcfg->force_reauth,
		PBC_GETVAR_SESSION_REAUTH,
		  dcfg->session_reauth); 

	DebugMsg((DEST,"  granting request= %s\n",g_req_contents));

	libpbc_base64_encode((unsigned char *)g_req_contents, (unsigned char *)e_g_req_contents,
				strlen(g_req_contents));

	sprintf(new_cookie, "%s=%s; domain=%s; path=/; secure",
		PBC_G_REQ_COOKIENAME, 
		e_g_req_contents,
		Enterprise_Domain);

	DebugMsg((DEST,"  new_cookie= %s\n",new_cookie));

	if ( strlen(dcfg->force_reauth) > 0 )
		dcfg->force_reauth[0] = NULL;

	/* setup the client pull */
	sprintf(refresh, "%d; URL=%s", PBC_REFRESH_TIME, Web_Login);
    
	DebugMsg((DEST,"  refresh= %s\n",refresh));

	sprintf(szHeaders, "Content-Type: text/html\r\n"
		               "Set-Cookie: %s\r\n"
                       "Refresh: %s\r\n"
					   "Cache-Control: no-cache\r\n"
                       "Pragma: no-cache\r\n"
					   "Expires: Fri, 01-Jan-1970 00:00:01 GMT\r\n"
					   "\r\n",
		new_cookie,refresh);

	DebugMsg((DEST,"  AddResponseHeaders3= \n%s",szHeaders));

	pFC->AddResponseHeaders(pFC,szHeaders,0);

	DebugMsg((DEST,"  REQ_SEND_RESPONSE_HEADER \n"));


	pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
								"200 OK",NULL,NULL);

	strcpy(szTemp,"<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
	dwSize=strlen(szTemp);

	pFC->WriteClient (pFC, szTemp, &dwSize, 0);

	return OK;

}  /* Auth_Failed */


int Bad_User (HTTP_FILTER_CONTEXT* pFC)
{
	char szTemp[1024];
	DWORD dwSize;

	DebugMsg((DEST," Bad_User\n")); 

	if ( strlen(Error_Page) == 0 ) {

		DebugMsg((DEST,"  REQ_SEND_RESPONSE_HEADER",szTemp));

		pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
								"200 OK",NULL,NULL);

		sprintf(szTemp,"<B> User Authentication Failed!<br><br>"
			           " Please contact <a href=\"mailto:ntadmin@%s\">ntadmin@%s</a> </B> <br>",
			scfg.server_hostname,scfg.server_hostname);
		dwSize=strlen(szTemp);

		pFC->WriteClient (pFC, szTemp, &dwSize, 0);

	} else {

		sprintf(szTemp, "Content-Type: text/html\r\n"
                        "Refresh: %d; URL=%s%\r\n"
						"\r\n", 
			0, Error_Page);

		DebugMsg((DEST,"  AddResponseHeaders4= \n%s",szTemp));

		pFC->AddResponseHeaders(pFC,szTemp,0);

		DebugMsg((DEST,"  REQ_SEND_RESPONSE_HEADER \n"));

		pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
			"200 OK",NULL,NULL);

		strcpy(szTemp,"<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
		dwSize=strlen(szTemp);

		pFC->WriteClient (pFC, szTemp, &dwSize, 0);

	}

	return OK;

}  /* Bad_User */


int Is_Pubcookie_Auth (pubcookie_dir_rec *dcfg)
{
	DebugMsg((DEST," Is_Pubcookie_Auth\n"));
	
	if ( dcfg->creds != PBC_CREDS_NONE ) {
		return TRUE;
	}
	else {
		return FALSE;
	}

}  /* Is_Pubcookie_Auth */


/* a is from the cookie                                                       */
/* b is from the module                                                       */
int Pubcookie_Check_Version (unsigned char *a, unsigned char *b) 
{
	char szBuff[1024];
	DebugMsg((DEST," Pubcookie_Check_Version\n"));

	if ( a[0] == b[0] && a[1] == b[1] )
		return 1;
	if ( a[0] == b[0] && a[1] != b[1] ) {
		sprintf(szBuff,"[Pubcookie_Check_Version] Minor version mismatch cookie: %s your version: %s", a, b);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return 1;
	}

	return 0;

}  /* Pubcookie_Check_Version */


/* check and see if whatever has timed out                                    */
int Pubcookie_Check_Exp(time_t fromc, int exp)
{
	DebugMsg((DEST," Pubcookie_Check_Exp: "));
	
	if ( (fromc + exp) > time(NULL) ) {
			DebugMsg((DEST,"True\n"));

		return 1;
	}
	else {
			DebugMsg((DEST,"False\n"));
		return 0;
	}

}  /* Pubcookie_Check_Exp */


char *Get_Cookie (HTTP_FILTER_CONTEXT* pFC, char *name)
{

	char *cookie_header;
	char cookie_data[MAX_COOKIE_SIZE+1];
	char name_w_eq [256];
	char szBuff[1024];
	char *cookie, *ptr;
	DWORD cbSize, dwError;

	DebugMsg((DEST," Get_Cookie\n"));
      
	cookie_data[0] = NULL;
	cbSize = MAX_COOKIE_SIZE;
	if (!pFC->GetServerVariable(pFC,"HTTP_COOKIE",cookie_data,&cbSize)) {
		dwError = GetLastError();
		DebugMsg((DEST," GetServerVariable[HTTP_COOKIE] failed = %d (%x), buffer size= %d\n",
			dwError,dwError,cbSize));
		if ( dwError == ERROR_INSUFFICIENT_BUFFER) {  // Should quit if too much cookie
			sprintf(szBuff,"[Get_Cookie] Cookie Data too large : %d", 
				cbSize);
			ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
	//		return ERROR_INSUFFICIENT_BUFFER
		}
	//	else	
		return NULL;
	}

	if ( strlen(cookie_data) > Max_Cookie_Size )
		Max_Cookie_Size = strlen(cookie_data);

	    /* add an equal on the end of cookie name */
	strcpy(name_w_eq,name);
	strcat(name_w_eq,"=");

	DebugMsg((DEST,"  Looking for cookie name '%s' in (%d) (first 2000 bytes)\n%.2000s\n",
		name_w_eq,strlen(cookie_data),cookie_data));

	/* find the one that's pubcookie */

    if (!(cookie_header = strstr(cookie_data, name_w_eq)))
		return NULL;

	cookie_header += strlen(name_w_eq);

	ptr = cookie_header;
	while(*ptr) {
		if (*ptr == ';')
			*ptr = 0;
		ptr++;
	}
	
    cookie = (char *)pbc_malloc(strlen(cookie_header)+1);
	if (!cookie) {
		sprintf(szBuff,"[Get_Cookie] Error allocating memory");
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return NULL;
	}

	strcpy(cookie,cookie_header);

//	Blank_Cookie (name);   // Why Blank it ??

	DebugMsg((DEST,"  cookie(%d)= %s\n",strlen(cookie),cookie));

	return cookie;

}  /* Get_Cookie */


void Get_Effective_Values(HTTP_FILTER_CONTEXT* pFC,
						  HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char key[1024];
	HKEY hKey;
	DWORD dwRead;
	long rslt;
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	DebugMsg((DEST,"Get_Effective_Values\n"));  //debug


		// Find NT UserID and Password to use for this session based on appid
		// If Key not found for appid use "Default" entries if they exist

		strcpy (key, PUBKEY);
		strcat (key, dcfg->appid);
		strcpy (dcfg->pszUser,		   scfg.NTUserId);
		strcpy (dcfg->pszPassword,     scfg.Password);
				dcfg->inact_exp=	   scfg.inact_exp;
				dcfg->hard_exp=		   scfg.hard_exp;
		strcpy (dcfg->force_reauth,	   scfg.force_reauth);
				dcfg->session_reauth=  scfg.session_reauth;
				dcfg->AuthType=	       scfg.AuthType;
//				dcfg->logout=          scfg.logout;
		strcpy (dcfg->logout_dir,	   scfg.logout_dir);
		strcpy (dcfg->logout_redir_dir,	   scfg.logout_redir_dir);
		

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

/*			dwRead = sizeof (dcfg->logout);
			RegQueryValueEx (hKey, "Logout",
							 NULL, NULL, (LPBYTE) &dcfg->logout, &dwRead);*/

			dwRead = sizeof (dcfg->logout_dir);
			RegQueryValueEx (hKey, "Logout_Dir",
							 NULL, NULL, (LPBYTE) &dcfg->logout_dir, &dwRead);

			dwRead = sizeof (dcfg->logout_redir_dir);
			RegQueryValueEx (hKey, "Logout_Redir_Dir",
							 NULL, NULL, (LPBYTE) &dcfg->logout_redir_dir, &dwRead);

			dwRead = sizeof (key); key[0] = NULL;
			RegQueryValueEx (hKey, "AuthType",
							 NULL, NULL, (LPBYTE) key, &dwRead);
			if ( strlen(key) > 0 ) {
			if ( stricmp(key,NETID) == 0 ) 
				dcfg->AuthType = PBC_CREDS_CRED1;
			else
			if ( stricmp(key,SECURID) == 0 ) 
				dcfg->AuthType = PBC_CREDS_CRED3;
			else
				dcfg->AuthType = PBC_CREDS_NONE;
			}

			dwRead = sizeof (dcfg->default_url);
			RegQueryValueEx (hKey, "Default_Url",
							 NULL, NULL, (LPBYTE) dcfg->default_url, &dwRead);

			dwRead = sizeof (dcfg->timeout_url);
			RegQueryValueEx (hKey, "Timeout_Url",
							 NULL, NULL, (LPBYTE) dcfg->timeout_url, &dwRead);

		} else {
			DebugMsg((DEST, "*** Could not read Pubcookie registry key %s, Using Defaults\n",key,rslt));
		}
    
		RegCloseKey (hKey); 

		sprintf(dcfg->s_cookiename,"%s_%s",PBC_S_COOKIENAME,dcfg->appid);

		DebugMsg((DEST,"  NtUserId        : %s\n" ,dcfg->pszUser));
		DebugMsg((DEST,"  Inact_Exp       : %d\n" ,dcfg->inact_exp));
		DebugMsg((DEST,"  Hard_Exp        : %d\n" ,dcfg->hard_exp));
		DebugMsg((DEST,"  Force_Reauth    : %s\n" ,dcfg->force_reauth));
		DebugMsg((DEST,"  Session_Reauth  : %1d\n" ,dcfg->session_reauth));
//		DebugMsg((DEST,"  Logout          : %1d\n" ,dcfg->logout));
		DebugMsg((DEST,"  AuthType        : %c\n" ,dcfg->AuthType));
		DebugMsg((DEST,"  Default_Url     : %s\n" ,dcfg->default_url));
		DebugMsg((DEST,"  Timeout_Url     : %s\n" ,dcfg->timeout_url));
		DebugMsg((DEST,"  s_cookiename    : %s\n" ,dcfg->s_cookiename));
		DebugMsg((DEST,"  Logout_Dir      : %s\n" ,dcfg->logout_dir));
		DebugMsg((DEST,"  Logout_Redir_Dir: %s\n" ,dcfg->logout_redir_dir));




}  /* Get_Effective_Values */


void Add_Header_Values(HTTP_FILTER_CONTEXT* pFC,
					   HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char temp[16];
	pubcookie_dir_rec* dcfg;

	DebugMsg((DEST,"Add_Header_Values"));  //debug

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	// Set Pubcookie Appid, User and Creds level

	pHeaderInfo->AddHeader(pFC,PBC_Header_Server,scfg.server_hostname);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Appid,dcfg->appid);

//	pHeaderInfo->SetHeader(pFC,"REMOTE_USER",dcfg->user);
// Don't know how to override server variables so use our own

	pHeaderInfo->AddHeader(pFC,PBC_Header_User,dcfg->user);

	sprintf(temp,"%c",dcfg->creds);

	pHeaderInfo->AddHeader(pFC,PBC_Header_Creds,temp);

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

	DebugMsg((DEST,"User"));  //debug


    dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	DebugMsg((DEST," Pubcookie_User\n"));

    // First check to see if this directory needs protection

	// Fetch requested URL

    pHeaderInfo->GetHeader(pFC,"url",achUrl,&cbURL);

	DebugMsg((DEST,"  Requested URL : %s\n",achUrl));

	// Have to parse Query_String ourselves, server hasn't scanned it yet

	ptr = strchr(achUrl,'?');
	if (ptr) {
		*ptr++;
		strncpy(szBuff, ptr, strlen(ptr));
		szBuff[strlen(ptr)] = NULL;
		strcpy(dcfg->args,szBuff);
		DebugMsg((DEST,"  Query String  : %s\n",szBuff));
	}

	// Normalize the URL - take out all those nasty ../ and %xx

	pFC->ServerSupportFunction(pFC,SF_REQ_NORMALIZE_URL,
								achUrl,NULL,NULL);

	DebugMsg((DEST,"  Normalized URL: %s\n",achUrl));

	// set Uri
	strcpy(dcfg->uri,achUrl);

	// set Request Method
	dwBuffSize = sizeof(dcfg->method);
	pHeaderInfo->GetHeader(pFC,"method",dcfg->method,&dwBuffSize);

	DebugMsg((DEST,"  Request Method: %s\n",dcfg->method));

	// Get Application ID from first node

	strcpy((char *)dcfg->appid,"defaultapp");
	dcfg->user[0]  = NULL;
	dcfg->creds    = PBC_CREDS_NONE;
	dcfg->AuthType = scfg.AuthType;

	pachUrl = achUrl;

	if ( Ignore_Poll && strlen(pachUrl) == 1 ) {
		// Don't care about "/" - Possibly Network Dispatcher Polling
		return DECLINED;
	}

    *pachUrl++;		// skip over first '/'
    ptr = strchr(pachUrl,'/');
	if ( !ptr ) {
		if ( dcfg->AuthType == PBC_CREDS_NONE )
			// Don't care about these - no first directory/appid
			return DECLINED;
	} else {
		strncpy((char *)dcfg->appid, pachUrl, ptr-pachUrl);
		dcfg->appid[(ptr-pachUrl)] = NULL;
	}

	DebugMsg((DEST,"  appid        : %s\n",dcfg->appid));

	// Save Path unchanged so cookies will be returned properly
	// strcpy(dcfg->path_id,dcfg->appid);

	// Convert appid to lower case if not using COOKIE_PATH
#ifndef COOKIE_PATH
	strlwr(dcfg->appid);
#endif

	// Get userid, timeouts, AuthType, etc for this app
	Get_Effective_Values(pFC,pHeaderInfo);


	// Check for Credential Level Wanted which overrides url names

	if ( dcfg->AuthType != PBC_CREDS_NONE ) {
		DebugMsg((DEST,"  AuthType       : %s\n",szBuff));

		dcfg->creds = dcfg->AuthType;
		// change appid back to default if no app specific settings
		if ( dcfg->AuthType == scfg.AuthType )
			strcpy((char *)dcfg->appid,"defaultapp");
	}
	else {

	// Determine directory type
	pachUrl = ptr + 1;
	ptr = strchr(pachUrl,'/');
	if ( !ptr ) { 
		// Don't care about these
		dcfg->pszUser[0] = NULL;
		return DECLINED;
	}
	strncpy(szBuff, pachUrl, ptr-pachUrl); szBuff[ptr-pachUrl] = NULL;

	DebugMsg((DEST,"  dir type       : %s\n",szBuff));

	if ( stricmp((const char *)szBuff, PUBLIC) == 0 ) {
		// Set effective userid only, no pubcookie stuff
//		Get_Effective_Values(pFC,pHeaderInfo);
		Add_Header_Values   (pFC,pHeaderInfo);
		return DECLINED;
	}
	else	
	if ( stricmp((const char *)szBuff, NETID) == 0 )
		dcfg->creds = PBC_CREDS_CRED1;
	else
	if ( stricmp((const char *)szBuff, SECURID) == 0 )
		dcfg->creds = PBC_CREDS_CRED3;
	else
	if ( stricmp((const char *)szBuff, dcfg->logout_dir) == 0 ){
		dcfg->creds = PBC_CREDS_CRED1;
		dcfg->logout = 1;
	}
	else
	if ( stricmp((const char *)szBuff, dcfg->logout_redir_dir) == 0 ){
		dcfg->creds = PBC_CREDS_CRED1;
		dcfg->logout = 1;
		dcfg->logout_redir = 1;
	}
    else {
		// Don't care about these or should we reject now???
		dcfg->pszUser[0] = NULL;
		return DECLINED;
	}
	}

	// Can't see cookies unless we are SSL. Redirect to https if needed.

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT_SECURE",
							szBuff, &dwBuffSize);
	if ( strcmp(szBuff,"0") == 0 ) 
	{
		sprintf(szBuff, "Content-Type: text/html\r\n"
                        "Refresh: %d; URL=https://%s%s?%s\r\n"
						"\r\n", 
			0, dcfg->appsrvid, achUrl, dcfg->args);

		DebugMsg((DEST,"  AddResponseHeaders5= \n%s",szBuff));

		pFC->AddResponseHeaders(pFC,szBuff,0);

		DebugMsg((DEST,"  REQ_SEND_RESPONSE_HEADER \n"));

		pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
			"200 OK",NULL,NULL);

		strcpy(szBuff,"<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
		dwBuffSize=strlen(szBuff);

		pFC->WriteClient (pFC, szBuff, &dwBuffSize, 0);

		dcfg->failed = PBC_BAD_PORT;
		return OK;
	}


	DebugMsg((DEST,"  creds= %c\n",dcfg->creds));



	// Get userid, timeouts, etc for this app
	// Get_Effective_Values(pFC,pHeaderInfo); // done above

	// Set force reauth URL to requested URL if not "NFR"
	if ( strcmp(dcfg->force_reauth,PBC_NO_FORCE_REAUTH) != 0 )
		if ( strlen(dcfg->default_url) > 0 )
			strcpy((char *)dcfg->force_reauth,dcfg->default_url);
		else
			strcpy((char *)dcfg->force_reauth,achUrl);

    // Get Granting cookie or Session cookie
	// If '<cookie name>=' then client has bogus time and cleared cookie hasn't expired

	if( !(cookie = Get_Cookie(pFC,PBC_G_COOKIENAME)) || (strcmp(cookie,"")==0) ) {
		if (cookie) pbc_free(cookie);
		if( !(cookie = Get_Cookie(pFC,dcfg->s_cookiename)) || (strcmp(cookie,"")==0) ) {
			DebugMsg((DEST,"  Pubcookie_User: no cookies yet, must authenticate\n"));
			if (cookie) pbc_free(cookie);
			dcfg->failed = PBC_BAD_AUTH;
			return OK;
		}
		else {
		EnterCriticalSection(&Ctx_Plus_CS);

		if( ! (cookie_data = libpbc_unbundle_cookie(cookie, 
							 scfg.session_verf_ctx_plus, scfg.c_stuff)) ) {
			LeaveCriticalSection(&Ctx_Plus_CS);
			sprintf(szBuff,"[Pubcookie_User] Can't unbundle Session cookie for URL %s; remote_host: %s",
				dcfg->uri, dcfg->remote_host);
			ReportPFEvent("[PubcookieFilter]",szBuff,
						"","",EVENTLOG_ERROR_TYPE,3);
			dcfg->failed = PBC_BAD_SESSION_CERT;
			pbc_free(cookie);
			return OK;
		}

		LeaveCriticalSection(&Ctx_Plus_CS);	
		pbc_free(cookie);

		DebugMsg((DEST,"  Session Cookie Contents:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    serial= %d\n    create_ts= %d\n    last_ts= %d\n",
			(*cookie_data).broken.user,(*cookie_data).broken.version,(*cookie_data).broken.appsrvid,
			(*cookie_data).broken.appid,(*cookie_data).broken.type,(*cookie_data).broken.creds,
			(*cookie_data).broken.serial,(*cookie_data).broken.create_ts,(*cookie_data).broken.last_ts));

		strcpy(dcfg->user, (char *)(*cookie_data).broken.user);

		// maintain highest level of creds
		if ( dcfg->creds == PBC_CREDS_CRED1 && (*cookie_data).broken.creds == PBC_CREDS_CRED3 )
			 dcfg->creds = PBC_CREDS_CRED3;

		if( ! Pubcookie_Check_Exp((*cookie_data).broken.create_ts,dcfg->hard_exp)) {
			DebugMsg((DEST,"  Session cookie hard expired for user: %s create_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.create_ts,
                dcfg->hard_exp,
                (time(NULL)-(*cookie_data).broken.create_ts) ));
			if ( strcmp(dcfg->force_reauth,PBC_NO_FORCE_REAUTH) != 0 &&
				 strlen(dcfg->timeout_url) > 0 )
				strcpy((char *)dcfg->force_reauth,dcfg->timeout_url);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(cookie_data);
			return OK;
		}

		if(dcfg->inact_exp != -1 &&
			! Pubcookie_Check_Exp((*cookie_data).broken.last_ts,dcfg->inact_exp) ) {
			DebugMsg((DEST,"  Session cookie inact expired for user: %s last_ts: %ld timeout: %d elapsed: %ld\n",
                (*cookie_data).broken.user,
                (*cookie_data).broken.last_ts,
                dcfg->inact_exp,
                (time(NULL)-(*cookie_data).broken.last_ts) ));
			if ( strcmp(dcfg->force_reauth,PBC_NO_FORCE_REAUTH) != 0 &&
				 strlen(dcfg->timeout_url) > 0 )
				strcpy((char *)dcfg->force_reauth,dcfg->timeout_url);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(cookie_data);
			return OK;
		}

		} /* end if session cookie */

	}
	else {

		dcfg->has_granting = 1;

		/* the granting cookie gets blanked too early and another login */
		/* server loop is required, this just speeds up that loop */
		if( strncmp(cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0 ) {
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(cookie);
			return OK;
		}
		EnterCriticalSection(&Ctx_Plus_CS);

		if( !(cookie_data = libpbc_unbundle_cookie(cookie,
							scfg.granting_verf_ctx_plus, scfg.c_stuff)) ) {
			LeaveCriticalSection(&Ctx_Plus_CS);
			sprintf(szBuff,"[Pubcookie_User] Can't unbundle Granting cookie for URL %s; remote_host: %s", 
				dcfg->uri, dcfg->remote_host);
			ReportPFEvent("[PubcookieFilter]",szBuff,
				  "","",EVENTLOG_ERROR_TYPE,3);
			dcfg->failed = PBC_BAD_GRANTING_CERT;
			pbc_free(cookie);
			return OK;
		}

		LeaveCriticalSection(&Ctx_Plus_CS);
		pbc_free(cookie);

		DebugMsg((DEST,"  Granting Cookie Contents:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    serial= %d\n    create_ts= %d\n    last_ts= %d\n",
			(*cookie_data).broken.user  ,(*cookie_data).broken.version  ,(*cookie_data).broken.appsrvid,
			(*cookie_data).broken.appid,(*cookie_data).broken.type     ,(*cookie_data).broken.creds,
			(*cookie_data).broken.serial,(*cookie_data).broken.create_ts,(*cookie_data).broken.last_ts));

		strcpy(dcfg->user,(const char *)(*cookie_data).broken.user);

		// maintain highest level of creds
		if ( dcfg->creds == PBC_CREDS_CRED1 && (*cookie_data).broken.creds == PBC_CREDS_CRED3 )
			 dcfg->creds = PBC_CREDS_CRED3;

		if( ! Pubcookie_Check_Exp((*cookie_data).broken.create_ts, PBC_GRANTING_EXPIRE) ) {
			sprintf(szBuff,"[Pubcookie_User] Granting cookie expired for user: %s  elapsed: %d limit: %d; remote_host: %s", 
				(*cookie_data).broken.user,(time(NULL)-(*cookie_data).broken.create_ts), PBC_GRANTING_EXPIRE, dcfg->remote_host);
			ReportPFEvent("[PubcookieFilter]",szBuff,
						"","",EVENTLOG_INFORMATION_TYPE,2);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(cookie_data);
			return OK;
		}

	} /* end if granting cookie */

	/* check appid */
	current_appid = dcfg->appid;
	if( _strnicmp((const char *)current_appid, (const char *)(*cookie_data).broken.appid, 
					sizeof((*cookie_data).broken.appid)-1) != 0 ) {
	//	sprintf(szBuff,"[Pubcookie_User] Wrong appid; current: %s cookie: %s; remote_host: %s", 
	//		current_appid, (*cookie_data).broken.appid, dcfg->remote_host);
	//	ReportPFEvent("[PubcookieFilter]",szBuff,
	//         "","",EVENTLOG_ERROR_TYPE,3);
		dcfg->failed = PBC_BAD_AUTH;   // PBC_BAD_APPID;  // Left over from failed application
		pbc_free(cookie_data);
		return OK;
	}

	/* make sure this cookie is for this server */
	/* Use server_hostname instead of appsrvid so we only need one c_key per server */
	if( _strnicmp((const char *)scfg.server_hostname, (const char *)(*cookie_data).broken.appsrvid, 
					sizeof((*cookie_data).broken.appsrvid)-1) != 0 ) {
		sprintf(szBuff,"[Pubcookie_User] Wrong app server id; current: %s cookie: %s; remote_host: %s", 
				scfg.server_hostname, (*cookie_data).broken.appsrvid, dcfg->remote_host);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_INFORMATION_TYPE,2);
		dcfg->failed = PBC_BAD_AUTH;  // PBC_BAD_SERVERID;
		pbc_free(cookie_data);
		return OK;  
	}

	if( !Pubcookie_Check_Version((*cookie_data).broken.version, 
			(unsigned char *)PBC_VERSION)){
		sprintf(szBuff,"[Pubcookie_User] Wrong version id; module: %d cookie: %d", 
				PBC_VERSION, (*cookie_data).broken.version);
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		dcfg->failed = PBC_BAD_VERSION;
		pbc_free(cookie_data);
		return OK;
	}

	if(dcfg->creds == PBC_CREDS_CRED1 ) {
		if( (*cookie_data).broken.creds != PBC_CREDS_CRED1 &&
			(*cookie_data).broken.creds != PBC_CREDS_CRED3    ) {
			sprintf(szBuff,"[Pubcookie_User] Wrong creds directory; %c cookie: %c", 
				PBC_CREDS_CRED1, (*cookie_data).broken.creds);
			ReportPFEvent("[PubcookieFilter]",szBuff,
				  "","",EVENTLOG_ERROR_TYPE,3);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(cookie_data);
			return OK;
		} else {
			dcfg->creds = (*cookie_data).broken.creds;   // Use Creds from Cookie
			}
	}
	else
	if(dcfg->creds == PBC_CREDS_CRED3 ) {
		if( (*cookie_data).broken.creds != PBC_CREDS_CRED3 ) {
			sprintf(szBuff,"  Pubcookie_User: Wrong creds directory; %c cookie: %c", 
				PBC_CREDS_CRED3, (*cookie_data).broken.creds);
			ReportPFEvent("[PubcookieFilter]",szBuff,
				  "","",EVENTLOG_ERROR_TYPE,3);
			dcfg->failed = PBC_BAD_AUTH;
			pbc_free(cookie_data);
			return OK;
		}
	}

	pbc_free(cookie_data);

	return OK;

}  /* Pubcookie_User */


int Pubcookie_Auth (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* dcfg;
 	DebugMsg((DEST,"Auth"));  //debug

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	DebugMsg((DEST," Pubcookie_Auth\n"));

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
	char new_cookie[START_COOKIE_SIZE];
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;
	char szBuff[1025];
	DWORD dwBuffSize;

	DebugMsg((DEST," Pubcookie_Typer\n"));


	if( !Is_Pubcookie_Auth(dcfg) ) 
		return DECLINED;

	DebugMsg((DEST,"  Has_Granting= %d, Failed= %d\n",dcfg->has_granting,dcfg->failed));

	if (dcfg->has_granting ) {

		/* clear granting cookie */
		Clear_Cookie(pFC,PBC_G_COOKIENAME,Enterprise_Domain,"/");

		first_time_in_session = 1;
		dcfg->has_granting = 0;
	}

	if (!dcfg->failed) {
	/* if the inactivity timeout is turned off don't send a session cookie 
	everytime, but be sure to send a session cookie if it's the first time
	in the app or if we're logging out.
		*/
		if (dcfg->inact_exp > 0 || first_time_in_session || dcfg->logout) {
			
			DebugMsg((DEST,"  Creating Session Cookie:\n    user= %s\n    version= %s\n    appsrvid= %s\n    appid= %s\n    type= %c\n    creds= %c\n    serial= %d\n    create_ts= %d\n    last_ts= %d\n",
				dcfg->user,PBC_VERSION,scfg.server_hostname,
				dcfg->appid,PBC_COOKIE_TYPE_S,dcfg->creds,
				(scfg.serial_s_sent+1),0,0));
			
			EnterCriticalSection(&Ctx_Plus_CS);
			
			cookie = libpbc_get_cookie((unsigned char *)dcfg->user, 
				PBC_COOKIE_TYPE_S, dcfg->creds, scfg.serial_s_sent++, (unsigned char *)scfg.server_hostname, 
				(unsigned char *)dcfg->appid, scfg.session_sign_ctx_plus, scfg.c_stuff);
			
			LeaveCriticalSection(&Ctx_Plus_CS);
			
			//  If we're logging out, clear the cookie.
			
			if (dcfg->logout) {
#ifdef COOKIE_PATH
				if ( strcmp(dcfg->appid,"defaultapp") == 0 )
					strcpy(szBuff,"/");
				else 
					sprintf(szBuff,"/%s",dcfg->appid);
				
#else
				strcpy(szBuff,"/");
#endif
				
				pbc_free(cookie);
				Clear_Cookie(pFC,dcfg->s_cookiename,dcfg->appsrvid,szBuff); 
				DebugMsg((DEST,"   Cleared Session Cookie....\n"));
				
				if (dcfg->logout_redir) {
					sprintf(szBuff, "Content-Type: text/html\r\n"
                        "Refresh: 0; URL=http://google.com\r\n"
		 			    "Cache-Control: no-cache\r\n"
                        "Pragma: no-cache\r\n"
					    "Expires: Fri, 01-Jan-1970 00:00:01 GMT\r\n"
						"\r\n");
					
					DebugMsg((DEST,"  AddResponseHeaders= \n%s",szBuff));
					
					pFC->AddResponseHeaders(pFC,szBuff,0);
					
					DebugMsg((DEST,"  REQ_SEND_RESPONSE_HEADER \n"));
					
					pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
						"200 OK",NULL,NULL);
					
					strcpy(szBuff,"<HTML><BODY BGCOLOR=\"#FFFFFF\"></BODY></HTML>\n");
					dwBuffSize=strlen(szBuff);
					
					pFC->WriteClient (pFC, szBuff, &dwBuffSize, 0);
					
					dcfg->failed = PBC_BAD_PORT;
					dcfg->handler = PBC_BAD_PORT;
					return OK;
					
				}
				else {
					return DECLINED;  // continue serving the logout page if we're not redirecting
				}
				//strncpy((char *)cookie,"",strlen((char *)cookie));
			}
			
			
#ifdef COOKIE_PATH
			if ( strcmp(dcfg->appid,"defaultapp") == 0 )
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
#else
			
			sprintf(new_cookie, "Set-Cookie: %s_%s=%s; domain=%s; path=/; secure\r\n", 
				PBC_S_COOKIENAME, dcfg->appid,
				cookie, 
				dcfg->appsrvid);
			//	dcfg->appid);	// Gave up on putting a path on the cookie since
			// browsers will not return it if case on URL does not
			// match. Too bad, wanted to limit amount of cookie data
			// being sent to each app, limited to 4096 bytes.

			
#endif
			pbc_free(cookie);
			
			DebugMsg((DEST,"  AddResponseHeaders1= \n%s",new_cookie));
			
			pFC->AddResponseHeaders(pFC,new_cookie,0);
			
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
	char szBuff[1024];

	// The version of the web server this is running on
	DebugMsg(( DEST, "\nPBC_GetFilterVersion: Web Server is version is %d.%d\n",
				HIWORD( pVer->dwServerFilterVersion ),
				LOWORD( pVer->dwServerFilterVersion ) ));

	// Filter version we expect.
	pVer->dwFilterVersion =  HTTP_FILTER_REVISION; // MAKELONG( 0, 4 ); Version 4.0

	// The description
	strcpy( pVer->lpszFilterDesc, Pubcookie_Version );
	
	sprintf(szBuff,"[GetFilterVersion] %s",Pubcookie_Version);
	ReportPFEvent( "[PubcookieFilter]",
                   szBuff,
                   "",
                   "",
                   EVENTLOG_INFORMATION_TYPE,
                   2 ); 

	// Only need two marked below for functionality, rest for debug

	Notify_Flags =  ( SF_NOTIFY_SECURE_PORT         |
					  SF_NOTIFY_NONSECURE_PORT      |
//					  SF_NOTIFY_READ_RAW_DATA       | // Only for Global Filters
					  SF_NOTIFY_PREPROC_HEADERS     | // ** Needed
					  SF_NOTIFY_URL_MAP             |
					  SF_NOTIFY_AUTHENTICATION      | // ** Needed
					  SF_NOTIFY_ACCESS_DENIED       |
					  SF_NOTIFY_SEND_RESPONSE       |
//					  SF_NOTIFY_SEND_RAW_DATA       |  // Too many debug calls
					  SF_NOTIFY_END_OF_REQUEST      |
					  SF_NOTIFY_LOG                 |
					  SF_NOTIFY_END_OF_NET_SESSION  |
					  SF_NOTIFY_ORDER_DEFAULT );

	pVer->dwFlags = Notify_Flags;

	return TRUE;

}  /* GetFilterVersion */


DWORD OnReadRawData (HTTP_FILTER_CONTEXT *pFC,
                     HTTP_FILTER_RAW_DATA *pRawDataInfo)
{
	DebugMsg((DEST,"\nPBC_OnReadRawData\n"));
	DebugMsg((DEST,"  Revision: x%x\n",pFC->Revision));
	DebugMsg((DEST,"  Secure  : x%x\n",pFC->fIsSecurePort));

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnReadRawData */


DWORD OnPreprocHeaders (HTTP_FILTER_CONTEXT* pFC,
                        HTTP_FILTER_PREPROC_HEADERS* pHeaderInfo)
{
	char szBuff[1024];
	char achUrl[1024];
//	char *ptr;
	DWORD dwBuffSize=1024;
	DWORD return_rslt;
//	unsigned long net_addr;
//	hostent *hp;
	pubcookie_dir_rec* dcfg;
	time_t ltime;

	// IBM Network Dispatcher probes web sites with a URL of "/" and command of HEAD
	// bail quickly if this is the case

	achUrl[0]= NULL; dwBuffSize=1024;
	pHeaderInfo->GetHeader(pFC, "url",
							achUrl, &dwBuffSize);

	if ( Ignore_Poll && strcmp(achUrl,"/") == 0 ) {
		pFC->ServerSupportFunction(pFC,SF_REQ_DISABLE_NOTIFICATIONS,
								NULL,Notify_Flags,NULL);
		return SF_STATUS_REQ_NEXT_NOTIFICATION;
	}

	Total_Requests++;

	time(&ltime);

	DebugMsg((DEST,"\n %s \n PBC_OnPreprocHeaders\n",ctime(&ltime)));

	if ( stricmp(achUrl,"/PubcookieFilter_Reset") == 0 ) {
		DebugMsg((DEST,"  Requested URL  : %s\n\n",achUrl));
		Read_Default_Reg_Settings ();

		DebugMsg((DEST,"  REQ_SEND_RESPONSE_HEADER \n"));

		pFC->ServerSupportFunction(pFC,SF_REQ_SEND_RESPONSE_HEADER,
								"200 OK",NULL,NULL);
		sprintf(szBuff,"<HTML><B> PubcookieFilter Defaults Reset </B> <br></HTML>");
		dwBuffSize=strlen(szBuff);
		pFC->WriteClient (pFC, szBuff, &dwBuffSize, 0);
		return SF_STATUS_REQ_FINISHED;
	}

	pFC->pFilterContext = pbc_malloc(sizeof(pubcookie_dir_rec));
	//		(VOID*) pFC->AllocMem(pFC,sizeof(pubcookie_dir_rec),0);

	if (!pFC->pFilterContext) {
		sprintf(szBuff,"[PBC_OnPreprocHeaders] Error allocating memory");
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return SF_STATUS_REQ_ERROR;
	}

	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	memset(dcfg,0,sizeof(pubcookie_dir_rec));

//	dcfg->inact_exp = scfg.inact_exp;
//	dcfg->hard_exp  = scfg.hard_exp;

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "INSTANCE_ID",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Instance ID    : %s\n",szBuff));

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "REMOTE_HOST",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Remote_Host    : %s\n",szBuff));
	strcpy(dcfg->remote_host,szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "HTTP_REFERER",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Referer        : %s\n",szBuff));

	DebugMsg((DEST,"  Requested URL  : %s\n",achUrl));
	
	szBuff[0]= NULL; dwBuffSize=1024;
	pHeaderInfo->GetHeader(pFC, "method",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Request_Method : %s\n",szBuff));

	szBuff[0]= NULL; dwBuffSize=1024;
	pHeaderInfo->GetHeader(pFC, "Content-Length:",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Content_Length : %s\n",szBuff));

	if ( (unsigned int)atoi(szBuff) > Max_Content_Length )
		Max_Content_Length = atoi(szBuff);

	DebugMsg((DEST,"  HttpStatus     : %d\n",pHeaderInfo->HttpStatus));
 
	szBuff[0]= NULL; dwBuffSize=1024; 
	pFC->GetServerVariable(pFC, "URL",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Server URL     : %s\n",szBuff));

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT_SECURE",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Server Secure  : %s\n",szBuff));
   
	szBuff[0]= NULL; dwBuffSize=1024;  
	pFC->GetServerVariable(pFC,"SERVER_NAME",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Server SERVER_NAME: %s\n",szBuff));

	strcpy(dcfg->appsrvid, szBuff);   // Use SERVER_NAME for appsrvid

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"LOCAL_ADDR",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Server LOCAL_ADDR : %s\n",szBuff));

	// Don't use reverse lookup for appsrvid. Breaks cname->server case (alias).
/*
	net_addr = inet_addr(szBuff);

	if ( !(hp = gethostbyaddr((const char *)&net_addr,sizeof(net_addr),AF_INET)) ) {
		sprintf(szBuff,"[PBC_OnPreprocHeaders] gethostbyaddr failed, LastErr= %d",
					WSAGetLastError());
		ReportPFEvent("[PubcookieFilter]",szBuff,
               "","",EVENTLOG_ERROR_TYPE,3);
		return SF_STATUS_REQ_ERROR;
	}

	DebugMsg((DEST,"  gethostbyaddr = %s\n",  //    alias[0]= %s\n",
			hp->h_name)); // ,hp->h_aliases[0]));

	// May need to search through aliases if we have local hosts file
	strncpy(dcfg->appsrvid, hp->h_name, PBC_APPSRV_ID_LEN);

*/

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"SERVER_PORT",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Server SERVER_PORT: %s\n",szBuff));
	strcpy(dcfg->appsrv_port,szBuff);
	// Force port 80 or 443(ssl) to null
	if ( strcmp(dcfg->appsrv_port, "80") == 0 ||
	 	 strcmp(dcfg->appsrv_port,"443") == 0    )
		strcpy(dcfg->appsrv_port,"");

//	szBuff[0]= NULL; dwBuffSize=1024;
//	pFC->GetServerVariable(pFC,"QUERY_STRING",
//							szBuff, &dwBuffSize);
//	DebugMsg((DEST,"  Server QUERY_STRING: %s\n",szBuff));

//	szBuff[0]= NULL; dwBuffSize=1024;
//	pHeaderInfo->GetHeader(pFC,"QUERY_STRING:",
//							szBuff, &dwBuffSize);
//	DebugMsg((DEST,"  Header QUERY_STRING: %s\n",szBuff));
//	strcpy(dcfg->args,szBuff);

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC,"HTTP_HOST",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Server HTTP_HOST  : %s\n",szBuff));

	return_rslt = SF_STATUS_REQ_NEXT_NOTIFICATION;
	dcfg->pszUser[0] = NULL;    // For OnAuth

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
				default:
					sprintf(szBuff,"[PBC_OnPreprocHeaders] Unexpected dcfg->handler value = %d",
						dcfg->handler);
					ReportPFEvent("[PubcookieFilter]",szBuff,
						"","",EVENTLOG_ERROR_TYPE,3);
					return_rslt = SF_STATUS_REQ_ERROR;
					break;
				}
			else
				Hide_Cookies(pFC,pHeaderInfo);
//		else
//			Hide_Cookies(pFC,pHeaderInfo);
	else
		Hide_Cookies(pFC,pHeaderInfo);

	DebugMsg((DEST," OnPreprocHeaders returned x%X\n",return_rslt));
	
	return return_rslt;

} /* OnPreprocHeaders */


DWORD OnUrlMap (HTTP_FILTER_CONTEXT* pFC, 
			    HTTP_FILTER_URL_MAP* pUrlMapInfo)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnUrlMap (%s)\n",dcfg->remote_host));
	}else {
		DebugMsg((DEST,"PBC_OnUrlMap\n"));
	}

	DebugMsg((DEST,"  PhysicalPath: %s\n",pUrlMapInfo->pszPhysicalPath));

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

} /* OnUrlMap */


DWORD OnAuthentication (HTTP_FILTER_CONTEXT* pFC,
                        HTTP_FILTER_AUTHENT* pAuthInfo)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnAuthentication (%s)\n",dcfg->remote_host));
	} else {
		DebugMsg((DEST,"PBC_OnAuthentication\n"));
	}

	DebugMsg((DEST,"  Old UserName: %s\n",pAuthInfo->pszUser));
//	DebugMsg((DEST,"  Old Password: %s\n",pAuthInfo->pszPassword));

	if ( dcfg )
	if ( strlen(dcfg->pszUser) > 0 ) {
		// Give the mapped user/password back to the server
		strcpy(pAuthInfo->pszUser    , dcfg->pszUser);
		strcpy(pAuthInfo->pszPassword, dcfg->pszPassword);

		DebugMsg((DEST,"  New UserName : %s\n",pAuthInfo->pszUser));
		DebugMsg((DEST,"  New PW length: %d\n",strlen(pAuthInfo->pszPassword)));
	}

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnAuthentication */


DWORD OnAccessDenied (HTTP_FILTER_CONTEXT* pFC, 
					  HTTP_FILTER_ACCESS_DENIED* pDenyInfo)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnAccessDenied (%s)\n",dcfg->remote_host));
	} else {
		DebugMsg((DEST,"PBC_OnAccessDenied\n"));
	}

	DebugMsg((DEST,"  URL   : %s\n",pDenyInfo->pszURL));
	DebugMsg((DEST,"  PATH  : %s\n",pDenyInfo->pszPhysicalPath));
	DebugMsg((DEST,"  Reason: x%x\n",pDenyInfo->dwReason));

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnAccessDenied */


DWORD OnSendResponse (HTTP_FILTER_CONTEXT* pFC,
                      HTTP_FILTER_SEND_RESPONSE* pResponseInfo)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnSendResponse (%s)\n",dcfg->remote_host));
	} else {
		DebugMsg((DEST,"PBC_OnSendResponse\n"));
	}

	DebugMsg((DEST,"  HttpStatus: %d\n",pResponseInfo->HttpStatus));

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnSendResponse */ 


DWORD OnSendRawData (HTTP_FILTER_CONTEXT* pFC,
                     HTTP_FILTER_RAW_DATA* pRawDataInfo)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnSendRawData (%s)\n",dcfg->remote_host));
	} else {
		DebugMsg((DEST,"PBC_OnSendRawData\n"));
	}

	DebugMsg((DEST,"  Sending(%d): \n%.*s\n",
		pRawDataInfo->cbInData,pRawDataInfo->cbInData,pRawDataInfo->pvInData));

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnSendRawData */


DWORD OnEndOfRequest (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnEndOfRequest (%s)\n",dcfg->remote_host));
	} else {
		DebugMsg((DEST,"PBC_OnEndOfRequest\n"));
	}
			
	// OnEndOfNetSession is not called consistantly for each request,
	// free here instead.
	// Assumes we don't need this structure in OnLog below
	
	pbc_free(pFC->pFilterContext);

	pFC->pFilterContext = NULL;   // Force to Null so we don't try to free twice

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnEndOfRequest */


DWORD OnLog (HTTP_FILTER_CONTEXT* pFC, 
		  	 HTTP_FILTER_LOG* pLogInfo)
{
	char szBuff[1024];
	DWORD dwBuffSize;

	DebugMsg((DEST,"PBC_OnLog\n"));

	szBuff[0]= NULL; dwBuffSize=1024;
	pFC->GetServerVariable(pFC, "INSTANCE_ID",
							szBuff, &dwBuffSize);
	DebugMsg((DEST,"  Instance ID   : %s\n",szBuff));

	DebugMsg((DEST,"  ClientHostName: %s\n",pLogInfo->pszClientHostName));
	DebugMsg((DEST,"  ClientUserName: %s\n",pLogInfo->pszClientUserName));
	DebugMsg((DEST,"  ServerName    : %s\n",pLogInfo->pszServerName));
	DebugMsg((DEST,"  Operation     : %s\n",pLogInfo->pszOperation));
	DebugMsg((DEST,"  Target        : %s\n",pLogInfo->pszTarget));
	DebugMsg((DEST,"  Parameters    : %s\n",pLogInfo->pszParameters));
	DebugMsg((DEST,"  HttpStatus    : %d\n",pLogInfo->dwHttpStatus));
	DebugMsg((DEST,"  Win32Status   : x%x\n",pLogInfo->dwWin32Status));
	DebugMsg((DEST,"  BytesSent     : %d\n",pLogInfo->dwBytesSent));
	DebugMsg((DEST,"  BytesReceived : %d\n",pLogInfo->dwBytesRecvd));
	DebugMsg((DEST,"  ProcTime      : %d\n",pLogInfo->msTimeForProcessing));

	if ( strlen(pLogInfo->pszTarget) > Max_Url_Length )
		Max_Url_Length = strlen(pLogInfo->pszTarget);

	if ( strlen(pLogInfo->pszParameters) > Max_Query_String )
		Max_Query_String = strlen(pLogInfo->pszParameters);

	if ( pLogInfo->dwBytesSent > Max_Bytes_Sent )
		Max_Bytes_Sent = pLogInfo->dwBytesSent;

	if ( pLogInfo->dwBytesRecvd > Max_Bytes_Recvd )
		Max_Bytes_Recvd = pLogInfo->dwBytesRecvd;

	return SF_STATUS_REQ_NEXT_NOTIFICATION;

}  /* OnLog */


DWORD OnEndOfNetSession (HTTP_FILTER_CONTEXT* pFC)
{
	pubcookie_dir_rec* dcfg;
	dcfg = (pubcookie_dir_rec *)pFC->pFilterContext;

	if ( dcfg ) {
		DebugMsg((DEST,"PBC_OnEndOfNetSession (%s)\n",dcfg->remote_host));
	} else {
		DebugMsg((DEST,"PBC_OnEndOfNetSession\n"));
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
	char szBuff[1024];
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
		sprintf(szBuff,"[PBC_HttpFilterProc] Unknown notification type, %d",
					NotificationType);
		ReportPFEvent("[PubcookieFilter]",szBuff,
				"","",EVENTLOG_ERROR_TYPE,3);
		dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;
		break;
	}
   
	DebugFlush;

	return dwRet;

}  /* HttpFilterProc */


BOOL WINAPI TerminateFilter (DWORD dwFlags) 
{
	/* Called When Filter is Terminated */

	DebugMsg(( DEST, "\nPBC_TerminateFilter Called \n"));

	WSACleanup();

	libpbc_free_crypt(scfg.c_stuff);

	libpbc_free_md_context_plus(scfg.session_sign_ctx_plus);

	libpbc_free_md_context_plus(scfg.session_verf_ctx_plus);

	libpbc_free_md_context_plus(scfg.granting_verf_ctx_plus);

	Close_Debug_Trace ();

	DeleteCriticalSection(&Ctx_Plus_CS); 

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


//	DebugMsg(( DEST, "PBC_DllMain: fdwReason= %d\n",fdwReason));

    switch ( fdwReason )
    {
    case DLL_PROCESS_ATTACH:
		{

		// Make a guess at out Web Instance number 
		// This may be based on relative ISAPI filter position
		// May not work for all cases

		switch ( HIWORD(hinstDll) )
			{
			case 4096:							// (x10000000)
				strcpy(Instance,"1"); break;
			case  300:							// (x012C0000)
				strcpy(Instance,"2"); break;
			case  306:							// (x01320000)
				strcpy(Instance,"3"); break;
			case  312:							// (x01380000)
				strcpy(Instance,"4"); break;
			case  318:							// (x013E0000)
				strcpy(Instance,"5"); break;
			case  324:							// (x01440000)
				strcpy(Instance,"6"); break;
			case  330:							// (x014A0000)
				strcpy(Instance,"7"); break;
			case  336:							// (x01500000)
				strcpy(Instance,"8"); break;
			case  342:							// (x01460000)
				strcpy(Instance,"9"); break;
			default:
				break;
			}	

		// Initialize Pubcookie Stuff - and Set Debut Trace Flags

		fReturn = Pubcookie_Init ();

		DebugMsg(( DEST, "\nPBC_DllMain: DLL_PROCESS_ATTACH  pid= %d Hinstance= %d (x%.8X) Web Instance = %s\n",
			getpid(),HIWORD(hinstDll),hinstDll,Instance));

		if ( !fReturn )
			DebugMsg(( DEST, "\n*** Pubcookie_Init Failed !\n\n"));

        //
        //  We don't care about thread attach/detach notifications
        //
		
        DisableThreadLibraryCalls( hinstDll );

        break;
		} /* case DLL_PROCEDD_ATTACH */

    case DLL_THREAD_ATTACH:
		{

		DebugMsg(( DEST, "PBC_DllMain: DLL_THREAD_ATTACH\n"));

        break;
		} /* case DLL_THREAD_ATTACH */

    case DLL_THREAD_DETACH:
        {

		DebugMsg(( DEST, "PBC_DllMain: DLL_THREAD_DETACH\n"));

        break;
        } /* case DLL_THREAD_DETACH */

    case DLL_PROCESS_DETACH:
        {
				
		DebugMsg(( DEST, "PBC_DllMain: DLL_PROCESS_DETACH\n"));

        break;
        } /* case DLL_PROCESS_DETACH */

    default:
		{
        DebugMsg(( DEST, "PBC_DllMain: Unexpected Reason= %d\n",fdwReason));
        
		break;
		}
    }   /* switch */

  	DebugMsg(( DEST, "PBC_DllMain: Returning %d\n",fReturn)); DebugFlush;

    return ( fReturn);

}  /* DllMain() */
