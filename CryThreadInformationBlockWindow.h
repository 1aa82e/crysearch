#ifndef _CrySearch_CryThreadInformationBlockWindow_h_
#define _CrySearch_CryThreadInformationBlockWindow_h_

#include "CryDialogTemplate.h"
#include "NativeAPI.h"
#include "CrySearchArrayCtrl.h"

// When a process is opened, the TEB (Thread Environment Block) of each thread inside it can be
// displayed inside this window.
class CryThreadInformationBlockWindow : public CryDialogTemplate
{
private:
	Label mThreadWindowDescription;
	CrySearchArrayCtrl mThreadInfo;
	Label mThreadIsHiddenFromDebugger;
	Button mOk;
	
	void DialogClose();
	
	__declspec(noinline) void Initialize32(const TEB32* tib);
	
#ifdef _WIN64
	__declspec(noinline) void Initialize64(const TEB* tib);
#endif
	
	typedef CryThreadInformationBlockWindow CLASSNAME;
public:
	CryThreadInformationBlockWindow(const int threadId);
	~CryThreadInformationBlockWindow();	
};

#endif
