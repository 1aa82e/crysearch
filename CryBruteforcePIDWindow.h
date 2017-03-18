#ifndef _CrySearch_CryBruteforcePIDWindow_h_
#define _CrySearch_CryBruteforcePIDWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Represents the user interface component used to brute-force process ID's.
class CryBruteforcePIDWindow : public CryDialogTemplate
{
private:
	Label mPidResultCount;
	CrySearchArrayCtrl mPidResults;
	Button mBegin;
	Button mClose;

	void CloseWindow();
	void BruteForceBegin();
	void SetResultLabel(const int numres);

	typedef CryBruteforcePIDWindow CLASSNAME;
public:
	CryBruteforcePIDWindow();
	~CryBruteforcePIDWindow();
};

#endif