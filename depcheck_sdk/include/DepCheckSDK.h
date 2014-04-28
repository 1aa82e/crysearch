
#ifndef __DepCheckSDK_h__
#define __DepCheckSDK_h__


//
#define COM_NO_WINDOWS_H
#include <objbase.h>


#if defined( _WIN32 ) && !defined( _NO_COM)

DEFINE_GUID(IID_IDepCheck,  0xDC78FF48, 0x45C3, 0x48C7, 0xB0, 0xAD, 0x35, 0xFB, 0x03, 0xC0, 0xF9, 0x87);
DEFINE_GUID(IID_IDepResult, 0xD0EF8263, 0xC191, 0x4E28, 0xA9, 0x7D, 0x35, 0x05, 0xE5, 0x02, 0x74, 0x48);

#endif

#ifdef __cplusplus

#ifndef DECLSPEC_UUID
#if _MSC_VER >= 1100
#define DECLSPEC_UUID(x)    __declspec(uuid(x))
#else
#define DECLSPEC_UUID(x)
#endif
#endif


interface DECLSPEC_UUID("DC78FF48-45C3-48C7-B0AD-35FB03C0F987") IDepCheck;
interface DECLSPEC_UUID("D0EF8263-C191-4E28-A97D-3505E5027448") IDepResult;


// If you want to use ref-counting pointers around the depcheck objects,
// include comdef.h before including the DepCheck SDK.
// The pointers will be named after the classes, with Ptr appended.
// so IDepCheck will have a smart pointer named IDepCheckPtr
// see sdk/examples/cpp/main.cpp
#if defined(_COM_SMARTPTR_TYPEDEF)
_COM_SMARTPTR_TYPEDEF(IDepResult, __uuidof(IDepResult));
_COM_SMARTPTR_TYPEDEF(IDepCheck, __uuidof(IDepCheck));
#endif

#endif



#ifdef __cplusplus
extern "C"{
#endif 

const HRESULT DEP_S_SUCCEEDED     = MAKE_HRESULT( SEVERITY_SUCCESS, FACILITY_ITF, 0x200 + 0 );
const HRESULT DEP_S_ISPE32        = MAKE_HRESULT( SEVERITY_SUCCESS, FACILITY_ITF, 0x200 + 1 );
const HRESULT DEP_S_ISPE64        = MAKE_HRESULT( SEVERITY_SUCCESS, FACILITY_ITF, 0x200 + 2 );
const HRESULT DEP_E_NOTPEFILE     = MAKE_HRESULT( SEVERITY_ERROR, FACILITY_ITF,   0x200 + 11 );


#undef  INTERFACE
#define INTERFACE   IDepResult

DECLARE_INTERFACE_(IDepResult, IUnknown)
{
	BEGIN_INTERFACE

	// *** IUnknown methods ***
	STDMETHOD(QueryInterface)(THIS_
								_In_ REFIID riid,
								_Deref_out_ void **ppv) PURE;
	STDMETHOD_(ULONG,AddRef)(THIS) PURE;
	STDMETHOD_(ULONG,Release)(THIS) PURE;

	// *** IDepResult methods ***
	STDMETHOD_(BOOL,IsValidPEFile)(THIS) PURE;
	STDMETHOD_(BOOL,IsX64PEFile)(THIS) PURE;
	STDMETHOD_(BOOL,HasZoneIdentifier)(THIS) PURE;
	STDMETHOD_(BOOL,RemoveZoneIdentifier)(THIS) PURE;

	END_INTERFACE
};


#undef  INTERFACE
#define INTERFACE   IDepCheck

DECLARE_INTERFACE_(IDepCheck, IUnknown)
{
	BEGIN_INTERFACE

	// *** IUnknown methods ***
	STDMETHOD(QueryInterface)(THIS_ _In_ REFIID riid, _Deref_out_ void **ppv) PURE;
	STDMETHOD_(ULONG,AddRef)(THIS) PURE;
	STDMETHOD_(ULONG,Release)(THIS) PURE;

	// *** IDepCheck methods ***
	STDMETHOD(SystemInfoString)( THIS_ _Deref_out_ BSTR* lpOut ) PURE;
	STDMETHOD_(BOOL,IsWow64)(THIS) PURE;
	STDMETHOD_(BOOL,FindDllInfo)( THIS_
								_In_z_ LPCSTR lpLibFileName,
								_Deref_opt_out_ BSTR *lpDescription,
								_Deref_opt_out_ BSTR *lpUrl,
								_Deref_opt_out_ BSTR *lpUrl64) PURE;
	STDMETHOD(AnalysisFromFileA)( THIS_
								_In_z_ LPCSTR lpFileName,
								_Deref_out_ IDepResult **ppResultOut) PURE;
	STDMETHOD(AnalysisFromFileW)( THIS_
								_In_z_ LPCWSTR lpFileName,
								_Deref_out_ IDepResult **ppResultOut) PURE;
	STDMETHOD(AnalysisFromMemory)( THIS_
								_In_bytecount_(dataLength) BYTE *lpData,
								_In_ SIZE_T dataLength,
								_Deref_out_ IDepResult **ppResultOut) PURE;

	END_INTERFACE
};


const UINT DEPCHECK_SDK_VERSION = 1;


#ifndef DEPCHECK_NO_DECLSPEC
#ifdef DEPCHECK_EXPORTS
#define DEPCHECK_API __declspec(dllexport)
#else
#define DEPCHECK_API __declspec(dllimport)
#endif
#else
#define DEPCHECK_API
#endif



DEPCHECK_API
HRESULT STDMETHODCALLTYPE DepCheckCreate( _In_ UINT SDKVersion, _Deref_out_ IDepCheck **ppvObject );


//Helper functions

//Allocate a BSTR from a const WCHAR* string
DEPCHECK_API
BSTR STDMETHODCALLTYPE DepAllocString( _In_opt_z_ const OLECHAR * psz);

//Free a BSTR (All functions that have a BSTR* as argument expect the user to cleanup!)
DEPCHECK_API
VOID STDMETHODCALLTYPE DepFreeString( _In_opt_ BSTR str );

//Allocate a BSTR from a const char* string
DEPCHECK_API
BSTR STDMETHODCALLTYPE DepConvertStringToBSTR( _In_z_ const char* pSrc);


//Returns the number of DepCheck objects still alive.
//This is the accumulated result of all interfaces defined.
//Usefull for debugging memory leaks caused by missing calls to Interface->Release()
DEPCHECK_API
ULONG STDMETHODCALLTYPE DepGlobalObjectCount();

#ifdef __cplusplus
}
#endif

#endif


