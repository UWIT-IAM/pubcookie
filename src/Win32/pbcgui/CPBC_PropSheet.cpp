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

void CPBC_PropSheet::ReplaceSlashes(_TCHAR * buf) {
	_TCHAR *p = buf;

	while (p = wcschr(p,L'/')) {
		(_TCHAR) *p =  L'\\';
		p++;
	}
}

CPBC_PropSheet::CPBC_PropSheet() : m_cref(0)
{
	pwzService=NULL;
	pwzParentPath=NULL;
	pwzNode=NULL;
	pwzMetaPath=NULL;
	pwzMachineName=NULL;
	pwzInstance=NULL;
	pwzRegPath=NULL;
	OBJECT_CREATED
}


CPBC_PropSheet::~CPBC_PropSheet()
{
	if ( pwzService )
		::LocalFree(pwzService); 
	if ( pwzParentPath )
		::LocalFree(pwzParentPath);
	if ( pwzNode )
		::LocalFree(pwzNode);
	if ( pwzMetaPath )
		::LocalFree(pwzMetaPath);
	if ( pwzMachineName )
		::LocalFree(pwzMachineName);
	if ( pwzInstance )
		::LocalFree(pwzInstance);
	if ( pwzRegPath )
		::LocalFree(pwzRegPath);

    OBJECT_DESTROYED
}

///////////////////////
// IUnknown implementation
///////////////////////

STDMETHODIMP CPBC_PropSheet::QueryInterface(REFIID riid, LPVOID *ppv)
{
    if (!ppv)
        return E_FAIL;
    
    *ppv = NULL;
    
    if (IsEqualIID(riid, IID_IUnknown))
        *ppv = static_cast<IExtendPropertySheet *>(this);
    else if (IsEqualIID(riid, IID_IExtendPropertySheet))
        *ppv = static_cast<IExtendPropertySheet *>(this);
    
    if (*ppv) 
    {
        reinterpret_cast<IUnknown *>(*ppv)->AddRef();
        return S_OK;
    }
    
    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CPBC_PropSheet::AddRef()
{
    return InterlockedIncrement((LONG *)&m_cref);
}

STDMETHODIMP_(ULONG) CPBC_PropSheet::Release()
{
    if (InterlockedDecrement((LONG *)&m_cref) == 0)
    {
        // we need to decrement our object count in the DLL
        delete this;
        return 0;
    }
    
    return m_cref;
}

HRESULT CPBC_PropSheet::ExtractData( IDataObject* piDataObject,
					CLIPFORMAT   cfClipFormat,
					BYTE*        pbData,
					DWORD        cbData )
{
	HRESULT hr = S_OK;

	FORMATETC formatetc = {cfClipFormat, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
	STGMEDIUM stgmedium = {TYMED_HGLOBAL, NULL};

	stgmedium.hGlobal = ::GlobalAlloc(GPTR, cbData);
	do 
	{
		if (NULL == stgmedium.hGlobal)
		{
			hr = E_OUTOFMEMORY;
			break;
		}
		hr = piDataObject->GetDataHere( &formatetc, &stgmedium );
		if ( FAILED(hr) )
		{
			break;
		}

		BYTE* pbNewData = reinterpret_cast<BYTE*>(stgmedium.hGlobal);
		if (NULL == pbNewData)
		{
			hr = E_UNEXPECTED;
			break;
		}
		::memcpy( pbData, pbNewData, cbData );
	} while (FALSE); 

	if (NULL != stgmedium.hGlobal)
	{
		::GlobalFree(stgmedium.hGlobal);
	}
	return hr;
} 

HKEY CPBC_PropSheet::OpenKey(LPCTSTR szKey, REGSAM samDesired) {

	HKEY hKey,rhKey;
	_TCHAR localname[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD lsize = MAX_COMPUTERNAME_LENGTH + 1;

	//Support for Remote Registries 
	GetComputerName(localname,&lsize);
	if (!_wcsicmp(localname,pwzMachineName)) {
		rhKey = HKEY_LOCAL_MACHINE;
	}else {
		if (RegConnectRegistry(pwzMachineName,HKEY_LOCAL_MACHINE, &rhKey) != ERROR_SUCCESS) {
			MessageBox(hwndDlg,L"Error opening remote registry.  Values displayed may not be accurate.",L"Error",MB_ICONERROR);
		}
	}
	// Create and open key and subkey.
	if( RegCreateKeyEx(rhKey ,
		szKey,
		0, NULL, REG_OPTION_NON_VOLATILE,
		samDesired, NULL,
		&hKey, NULL) != ERROR_SUCCESS) 
	{
		return NULL ;
	}

	return hKey;

}

BOOL CPBC_PropSheet::WriteRegString(const _TCHAR* szKey,
              const _TCHAR* szValueName,
              const _TCHAR* szValue)
{
    HKEY hKey;
	
	if (!(hKey=OpenPBCKey(szKey,KEY_ALL_ACCESS)))
		return FALSE;

    // Set the Value.
    if (szValue != NULL)
    {
        RegSetValueEx(hKey, szValueName, 0, REG_SZ,
            (BYTE *)szValue,
            (_tcslen(szValue)+1)*sizeof(_TCHAR)) ;
		// If we just set the default value, delete the value from /
		if (!_wcsicmp(szKey,_T(PBC_DEFAULT_KEY))) {
			DeleteRegVal(L"",szValueName);
		}

    }

    RegCloseKey(hKey) ;
    return TRUE ;
}

void CPBC_PropSheet::DeleteRegVal(const _TCHAR* szKey, const _TCHAR* szValueName) 
{
    HKEY hKey;

	if ((hKey=OpenPBCKey(szKey,KEY_ALL_ACCESS))) {
		RegDeleteValue(hKey,szValueName);
	}

}

BOOL CPBC_PropSheet::WriteRegInt(const _TCHAR* szKey,
              const _TCHAR* szValueName,
              const _TCHAR* szValue)
{
    HKEY hKey;
	DWORD value;
	
	if (!(hKey=OpenPBCKey(szKey,KEY_ALL_ACCESS)))
		return FALSE;

    // Set the Value.
    if (szValue != NULL)
    {
		value = _wtoi(szValue);
        RegSetValueEx(hKey, szValueName, 0, REG_DWORD,
            (BYTE *)&value,
            sizeof(DWORD)) ;
		// If we just set the default value, delete the value from /
		if (!_wcsicmp(szKey,_T(PBC_DEFAULT_KEY))) {
			DeleteRegVal(L"",szValueName);
		}
    }

    RegCloseKey(hKey) ;
    return TRUE ;
}

void CPBC_PropSheet::ReadValAsString(LPTSTR key, int i, LPCTSTR defined_in_val) {
	HKEY hKey;
	_TCHAR RegBuff[BUFFSIZE];
	long debug;
	DWORD dwRead=BUFFSIZE*sizeof(_TCHAR);

	if (hKey = OpenKey(key,KEY_READ)) {
			if ((debug = RegQueryValueEx (hKey,directive[i].name.c_str(), NULL, NULL, (LPBYTE)RegBuff, &dwRead)) == ERROR_SUCCESS) {
			if (directive[i].type == D_FREE_INT || directive[i].type == D_BOUND_INT) {
				wchar_t tmpw[22];
				directive[i].value = _itow(*(DWORD *)RegBuff,tmpw,10);
			} else {
				directive[i].value = RegBuff;
			}
			directive[i].defined_in = defined_in_val;
		} 
		RegCloseKey (hKey); 
	} 
}

void CPBC_PropSheet::PopulateComboBox(HWND cb_handle)
{

	for (int i = 0; i <  NUM_DIRECTIVES; i++)
	{	
		LRESULT index = SendMessage(cb_handle, CB_ADDSTRING, 0, (LPARAM) (LPWSTR) directive[i].name.c_str());
		LRESULT debug = SendMessage(cb_handle, CB_SETITEMDATA, (WPARAM)index, (LPARAM)i );
	}

	LRESULT debug = SendMessage(cb_handle, CB_SETCURSEL, 0, 0);	// wparam = index, lparam = not used

}

BOOL CPBC_PropSheet::UpdateNewValue() {
	wchar_t value[BUFFSIZE];
	HWND hValueBox       = GetDlgItem(hwndDlg, IDC_ValueBox);
	HWND hValueEdit      = GetDlgItem(hwndDlg, IDC_ValueEdit);
	HWND hProps	         = GetDlgItem(hwndDlg, IDC_PROPS);

	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	UINT i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );

	if (directive[i].type == D_BOUND_INT || directive[i].type == D_BOUND_STRING) {
		index = SendMessage(hValueBox, CB_GETCURSEL, 0,0); 
		if (index == CB_ERR) { return FALSE; }
		LRESULT debug = SendMessage(hValueBox, CB_GETLBTEXT, (WPARAM)index, (LPARAM)value );
	} else {
		LRESULT debug = SendMessage(hValueEdit, WM_GETTEXT, (WPARAM)BUFFSIZE, (LPARAM)value );
	}

	directive[i].new_value = value;
	if (!_wcsicmp(directive[i].value.c_str(),value)) {
		return FALSE;
	} else {
		return TRUE;
	}
}

void CPBC_PropSheet::PopulatePage() {
	HWND hValueBox       = GetDlgItem(hwndDlg, IDC_ValueBox);
	HWND hValueEdit      = GetDlgItem(hwndDlg, IDC_ValueEdit);
	HWND hInheritedFrom  = GetDlgItem(hwndDlg, IDC_InheritedFrom);
	HWND hMoreInfo       = GetDlgItem(hwndDlg, IDC_MoreInfo);
	HWND hProps	         = GetDlgItem(hwndDlg, IDC_PROPS);

	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	LRESULT i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );

	Set_Delete_Button(i);

	if (directive[i].type == D_BOUND_INT || directive[i].type == D_BOUND_STRING) {
		ShowWindow(hValueEdit,SW_HIDE);
		ShowWindow(hValueBox,SW_SHOW);
		SendMessage(hValueBox,CB_RESETCONTENT,0,0);
		for(int vi=0;vi < NUM_BOUND_VAL;vi++) {
			if (directive[i].bound_val[vi].length()) {
				LRESULT index = SendMessage(hValueBox, CB_INSERTSTRING, -1, (LPARAM) (LPWSTR) directive[i].bound_val[vi].c_str());
			}
		}

		SendMessage(hValueBox, WM_SETTEXT, 0, (LPARAM) directive[i].new_value.c_str());
	} else {
		ShowWindow(hValueEdit,SW_SHOW);
		ShowWindow(hValueBox,SW_HIDE);
		SendMessage(hValueEdit, WM_SETTEXT, 0, (LPARAM) directive[i].new_value.c_str());
	}

	SendMessage(hMoreInfo, WM_SETTEXT, 0, (LPARAM) directive[i].description.c_str());
	SendMessage(hInheritedFrom, WM_SETTEXT, 0, (LPARAM) directive[i].defined_in.c_str());

}

BOOL CALLBACK CPBC_PropSheet::DialogProc(
                                              HWND hwndDlg,  // handle to dialog box
                                              UINT uMsg,     // message
                                              WPARAM wParam, // first message parameter
                                              LPARAM lParam  // second message parameter
                                              )
{

	if (uMsg == WM_INITDIALOG) {
		CPBC_PropSheet *pThis=reinterpret_cast<CPBC_PropSheet *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		pThis->hwndDlg=hwndDlg;                              //store property page handle in class
		SetWindowLongPtr(hwndDlg,DWLP_USER,(LONG_PTR)pThis); //store class pointer in property page
		pThis->SetupPropSheet();
	} else { 
		CPBC_PropSheet *pThis = reinterpret_cast<CPBC_PropSheet *>(reinterpret_cast<PROPSHEETPAGE *>(GetWindowLongPtr(hwndDlg,DWLP_USER)));  //retrieve class pointer from property page
		switch (uMsg) {
			case WM_COMMAND:
				if (HIWORD(wParam) == EN_CHANGE || HIWORD(wParam) == CBN_SELCHANGE) {
					if ((HWND)lParam == GetDlgItem(hwndDlg,IDC_PROPS)) {  //if the user changes directives
						pThis->PopulatePage();  //redraw page
					} else {
						if (pThis->UpdateNewValue()) {
							//if anything else changes, light the apply button
							SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0); 
						}
					}
				}
				if (wParam == IDC_Delete) { 
					pThis->DeleteValue();
					pThis->ReadSelectedValue();
					pThis->PopulatePage();
					SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0); //light apply
				} else if (wParam == IDC_Refresh) {
					pThis->ReadCurrentValues(); //refresh values
					pThis->PopulatePage();      //refresh page
				}
				break;

			case WM_DESTROY:
				break;

			case WM_NOTIFY:
				switch (((NMHDR *) lParam)->code) {
			case PSN_APPLY:
				pThis->UpdateNewValue();    //collect last-minute changes
				pThis->WriteValues();       //write new values
				pThis->ReadCurrentValues(); //refresh values
				pThis->PopulatePage();      //refresh page
				return PSNRET_NOERROR;
				}
				break;
		}
	}
	return FALSE;  //Seems to not fall through to parent page if you use DefWindowProc
	//return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

///////////////////////////////
// Interface IExtendPropertySheet
///////////////////////////////
HRESULT CPBC_PropSheet::CreatePropertyPages( 
	/* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
                                                 /* [in] */ LONG_PTR handle,
                                                 /* [in] */ LPDATAOBJECT lpIDataObject)
{
    PROPSHEETPAGE psp;
    HPROPSHEETPAGE hPage = NULL;

	// cache this handle so we can call MMCPropertyChangeNotify
    m_ppHandle = handle;
    
	UINT s_cfInstance =
		RegisterClipboardFormat(_T("ISM_SNAPIN_INSTANCE"));
	UINT s_cfMachineName =
		RegisterClipboardFormat(_T("ISM_SNAPIN_MACHINE_NAME"));
	UINT s_cfMetaPath =
		RegisterClipboardFormat(_T("ISM_SNAPIN_META_PATH"));
	UINT s_cfNode =
		RegisterClipboardFormat(_T("ISM_SNAPIN_NODE"));
	UINT s_cfParentPath =
		RegisterClipboardFormat(_T("ISM_SNAPIN_PARENT_PATH"));
	UINT s_cfService =
		RegisterClipboardFormat(_T("ISM_SNAPIN_SERVICE"));

	 if ( !lpProvider || !lpIDataObject )
  return E_POINTER;

 HRESULT hr = S_OK;

 DWORD dwLength = MAX_PATH * sizeof(WCHAR);

 pwzInstance = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwLength));
 pwzMachineName = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwLength));
 pwzMetaPath = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwLength));
 pwzNode = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwLength));
 pwzParentPath = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwLength));
 pwzService = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwLength));
 pwzRegPath = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, (dwLength*2)+1));

 if ( pwzInstance )
	 CPBC_PropSheet::ExtractString(lpIDataObject, s_cfInstance, pwzInstance, dwLength);
 if ( pwzMachineName )
	 CPBC_PropSheet::ExtractString(lpIDataObject, s_cfMachineName, pwzMachineName, dwLength);
 if ( pwzMetaPath )
	 CPBC_PropSheet::ExtractString(lpIDataObject, s_cfMetaPath, pwzMetaPath, dwLength);
 if ( pwzNode )
	 CPBC_PropSheet::ExtractString(lpIDataObject, s_cfNode, pwzNode, dwLength);
 if ( pwzParentPath )
	 CPBC_PropSheet::ExtractString(lpIDataObject, s_cfParentPath, pwzParentPath, dwLength);
 if ( pwzService )
	 CPBC_PropSheet::ExtractString(lpIDataObject, s_cfService, pwzService, dwLength);

 LPWSTR ppath = wcschr(pwzParentPath,L'/');
 if (ppath) {
	StringCbCopy(pwzRegPath, MAX_PATH*2 ,ppath+1);
	StringCbCat (pwzRegPath, MAX_PATH*2 ,L"/");
 } else {
	pwzRegPath[0] = 0;
 }
 StringCbCat(pwzRegPath, MAX_PATH*2 ,pwzNode);

 psp.dwSize = sizeof(PROPSHEETPAGE);
 psp.dwFlags = PSP_DEFAULT | PSP_USETITLE | PSP_USEICONID;
 psp.hInstance = g_hinst;
 psp.pszTemplate = MAKEINTRESOURCE(IDD_PROPPAGE);
 psp.pfnDlgProc = DialogProc;
 psp.lParam = reinterpret_cast<LPARAM>(this);
 psp.pszTitle = MAKEINTRESOURCE(IDS_PST_TAB_NAME);
 //psp.pszIcon = MAKEINTRESOURCE();

 hPage = CreatePropertySheetPage(&psp);
 _ASSERT(hPage);

 hr = lpProvider->AddPage(hPage);

 return hr;
}

HRESULT CPBC_PropSheet::QueryPagesFor( 
                                           /* [in] */ LPDATAOBJECT lpDataObject)
{
    return S_OK;
}

