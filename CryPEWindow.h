#ifndef _CrySearch_CryPEWindow_h_
#define _CrySearch_CryPEWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"

class CryPEWindow : public ParentCtrl
{
private:
	ToolBar mToolStrip;
	Splitter mSplitter;
	Splitter mRightPaneSplitter;
	CrySearchArrayCtrl mPeInformationCtrl;
	CrySearchArrayCtrl mSections;
	CrySearchArrayCtrl mDotNetInformation;
	
	void ToolBar(Bar& pBar);
	void SectionsListRightClick(Bar& pBar);
	void DotNetSectionsListRightClick(Bar& pBar);
	
	void RefreshPEWindow();
	void ResumeSuspendedProcess();
	void DumpSection();
	void DumpDotNetSection();
	
	typedef CryPEWindow CLASSNAME;
public:
	CryPEWindow();
	~CryPEWindow();
	
	void Initialize();
	void ClearList();
};

#endif
