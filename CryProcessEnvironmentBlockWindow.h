#ifndef _CrySearch_CryProcessEnvironmentBlockWindow_h_
#define _CrySearch_CryProcessEnvironmentBlockWindow_h_

#include "CryDialogTemplate.h"
#include "NativeAPI.h"
#include "CrySearchArrayCtrl.h"

// When a process is opened, the PEB (Process Environment Block) can be analyzed and displayed
// inside this window. The debug flag can be reset as well. (PEB->BeingDebugged)
class CryProcessEnvironmentBlockWindow : public CryDialogTemplate
{
private:
	BYTE* pIsBeingDebuggedPtr;

	Label mPEBWindowDescription;
	CrySearchArrayCtrl mPEBInfo;
	Button mOk;
	Button mResetDebugFlag;
	
	void Initialize();
	void DialogClose();
	void ResetDebugFlag();
	
	__declspec(noinline) void Initialize32(const PEB32* peb, const RTL_USER_PROCESS_PARAMETERS32* userparams);

#ifdef _WIN64
	__declspec(noinline) void Initialize64(const PEB* peb, const RTL_USER_PROCESS_PARAMETERS* userparams);
#endif
	
	typedef CryProcessEnvironmentBlockWindow CLASSNAME;
public:
	CryProcessEnvironmentBlockWindow(const Image& icon);
	~CryProcessEnvironmentBlockWindow();	
};

#endif