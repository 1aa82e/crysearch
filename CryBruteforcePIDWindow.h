#ifndef _CrySearch_CryBruteforcePIDWindow_h_
#define _CrySearch_CryBruteforcePIDWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Represents the user interface component used to brute-force process ID's.
class CryBruteforcePIDWindow : public CryDialogTemplate
{
private:
	CoWork mThreadPool;
	
	Label mPidResultCount;
	CrySearchArrayCtrl mPidResults;
	DropList mOptionsSelector;
	Button mBegin;
	ProgressIndicator mBruteForceProgress;
	Button mClose;

	void CloseWindow();
	void BruteForceBegin();
	void SetResultLabel(const int numres);
	
	void BruteForceWorker(const int id, const unsigned long begin, const unsigned long count);
	//void WorkerReportProcessFound(const Vector<BasicOpenProcessInfo>& intermediate);
	//void WorkerReportProcessFoundThreadSafe(const Vector<BasicOpenProcessInfo>& intermediate);

	typedef CryBruteforcePIDWindow CLASSNAME;
public:
	CryBruteforcePIDWindow();
	~CryBruteforcePIDWindow();
};

#endif