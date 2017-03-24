#ifndef _CrySearch_CryBruteforcePIDWindow_h_
#define _CrySearch_CryBruteforcePIDWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"
#include "ProcessUtil.h"

// Represents the user interface component used to brute-force process ID's.
class CryBruteforcePIDWindow : public CryDialogTemplate
{
private:
	Win32ProcessInformation tmpProc;

	Label mPidResultCount;
	CrySearchArrayCtrl mPidResults;
	Button mBegin;
	Button mClose;

	void CloseWindow();
	void BruteForceBegin();
	void SetResultLabel(const int numres);
	void ProcessResultWhenBar(Bar& pBar);
	void OpenBruteForcedProcess();

	typedef CryBruteforcePIDWindow CLASSNAME;
public:
	CryBruteforcePIDWindow();
	~CryBruteforcePIDWindow();
	
	Win32ProcessInformation* const GetSelectedProcess();
};

#endif