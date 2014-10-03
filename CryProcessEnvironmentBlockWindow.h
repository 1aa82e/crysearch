#ifndef _CrySearch_CryProcessEnvironmentBlockWindow_h_
#define _CrySearch_CryProcessEnvironmentBlockWindow_h_

#include "CryDialogTemplate.h"
#include "NativeAPI.h"

class CryProcessEnvironmentBlockWindow : public CryDialogTemplate
{
private:
	BYTE* pIsBeingDebuggedPtr;

	Label mPEBWindowDescription;
	ArrayCtrl mPEBInfo;
	Button mOk;
	Button mResetDebugFlag;
	
	void Initialize();
	void DialogClose();
	void ResetDebugFlag();
	
	__declspec(noinline) void Initialize32(const PEB32* peb);

#ifdef _WIN64
	__declspec(noinline) void Initialize64(const PEB* peb);
#endif
	
	typedef CryProcessEnvironmentBlockWindow CLASSNAME;
public:
	CryProcessEnvironmentBlockWindow(const Image& icon);
	~CryProcessEnvironmentBlockWindow();	
};

#endif