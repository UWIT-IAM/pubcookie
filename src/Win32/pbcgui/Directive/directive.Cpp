
#include <windows.h>
#include "pbc_config.h"
#include "gui_myconfig.h"
#include "CPBC_PropSheet.h"
#include "resource.h"
#include "globals.h"
#include <crtdbg.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
using namespace std;

#define libpbc_config_getint(p,n,d) libpbc_myconfig_getint(p,_T(n),d)
#define libpbc_config_getstring(p,n,d) libpbc_myconfig_getstring(p,_T(n),_T(d))

void CPBC_PropSheet::GetEffectiveValue(int i) {

	wchar_t key[BUFFSIZE+MAX_PATH], wszBuff[BUFFSIZE];
	wchar_t *ptr,*nptr;
	wstring defined_in_val;

	// First look in default key
    StringCbCopy (key, BUFFSIZE+MAX_PATH, _T(PBC_FILTER_KEY));
	StringCbCat  (key, BUFFSIZE+MAX_PATH, L"\\");
	StringCbCat  (key, BUFFSIZE+MAX_PATH, _T(PBC_DEFAULT_KEY));

	ReadValAsString(key,i,L"/");

	// Then root key  **Deprecated**
	//ReadValAsString(key,i,L"/");

	// Then traverse pwzRegPath
	StringCbCopy (key, BUFFSIZE, PBC_WEB_VAR_LOCATION);
	ptr = pwzRegPath;

	int first_node = 1;

	while ( ptr ) { // while we still have a '/' left to deal with

		nptr = ptr;
		ptr = wcschr(nptr,L'/');

		if (ptr) {
			wcsncpy(wszBuff, nptr, ptr-nptr);
			wszBuff[ptr-nptr] = NULL;
		}
		else {
			StringCbCopy(wszBuff,BUFFSIZE,nptr);
		}

		if (!wcslen(wszBuff)) {
			break;
		}


		defined_in_val += L"/";
		defined_in_val += wszBuff;

		if ( !wcsicmp(directive[i].name.c_str(),L"AppID") && first_node) {
				directive[i].value = wszBuff;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(default AppID node)";
		}
		first_node = 0;

		// Legacy hack for special tokens PBC_PUBLIC, UWNETID and SECURID
		if ((PBC_LEGACY_DIR_NAMES) && !wcsicmp(directive[i].name.c_str(),L"authtype")) {
			if ( !wcsicmp(wszBuff, PBC_NETID_NAME)) {
				directive[i].value = PBC_AUTHTYPE1;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			} else if (!wcsicmp(wszBuff, PBC_SECURID_NAME) ) {
				directive[i].value = PBC_AUTHTYPE3;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			} else if (!wcsicmp(wszBuff, PBC_PUBLIC_NAME) ) {
				directive[i].value = PBC_AUTHTYPE0;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			}
		}
		// Legacy hack for special tokens PBC_PUBLIC, UWNETID and SECURID
		if ((PBC_LEGACY_DIR_NAMES) && !wcsicmp(directive[i].name.c_str(),L"SetHeaderValues")) {
			if ( !wcsicmp(wszBuff, PBC_PUBLIC_NAME) ) {
				directive[i].value = L"1";
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			}
		}

		StringCbCat(key,BUFFSIZE,L"\\");
		StringCbCat(key,BUFFSIZE, wszBuff);

		ReadValAsString(key,i,defined_in_val.c_str());
	
		if (!ptr) {break;}
		ptr++;
	}
}

void CPBC_PropSheet::Set_Delete_Button(int i) {

	if (!_wcsicmp((directive[i].defined_in.c_str() + 1),pwzRegPath)) {
		EnableWindow(hDelete,TRUE);
	} else {
		EnableWindow(hDelete,FALSE);
	}
}

void CPBC_PropSheet::ReadSelectedValue() {

#	define DIRECTIVE_INIT
#	include "pbc_directives.h"
#	undef DIRECTIVE_INIT

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		GetEffectiveValue(i);
	}

	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );
	directive[i].new_value = directive[i].value;

}

void CPBC_PropSheet::ReadCurrentValues() {

#	define DIRECTIVE_INIT
#	include "pbc_directives.h"
#	undef DIRECTIVE_INIT

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		GetEffectiveValue(i);
		directive[i].new_value = directive[i].value;
	}
}

void CPBC_PropSheet::WriteValues() {
	wstring RegPath;

	if  (wcslen(pwzRegPath)) {
		RegPath = pwzRegPath;
	} else {
		RegPath = _T(PBC_DEFAULT_KEY);
	}

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		if (wcscmp(STR_PENDING_DELETION,directive[i].new_value.c_str())){
			if (wcsicmp(directive[i].value.c_str(),directive[i].new_value.c_str())) {
				if (directive[i].type == D_BOUND_INT || directive[i].type == D_FREE_INT) {
					WriteRegInt(RegPath.c_str(), directive[i].name.c_str(), directive[i].new_value.c_str());
				} else {
					WriteRegString(RegPath.c_str(), directive[i].name.c_str(), directive[i].new_value.c_str());
				}
			}
		} else { // Commit Delete
			if (!wcslen(pwzRegPath)) {  //Delete root directory values from default key only
				DeleteRegVal(_T(PBC_DEFAULT_KEY),directive[i].name.c_str());
			} else {
				DeleteRegVal(pwzRegPath,directive[i].name.c_str());
			}
		}
	}

}

HKEY CPBC_PropSheet::OpenPBCKey(LPCTSTR szKey, REGSAM samDesired) {
	_TCHAR szKeyBuf[BUFFSIZE] ;

	StringCbCopy (szKeyBuf, BUFFSIZE, PBC_WEB_VAR_LOCATION);
	StringCbCat  (szKeyBuf, BUFFSIZE+MAX_PATH, L"\\");
	StringCbCat(szKeyBuf,BUFFSIZE,szKey);
	ReplaceSlashes(szKeyBuf);

	return(OpenKey(szKeyBuf,samDesired));

}
