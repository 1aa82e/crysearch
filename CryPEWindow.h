#ifndef _CrySearch_CryPEWindow_h_
#define _CrySearch_CryPEWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"
#include "CrySearchArrayCtrl.h"

#pragma warning(disable : 4005)

class CryPEWindow : public ParentCtrl
{
private:
	ToolBar tBar;
	Splitter mSplitter;
	Splitter mRightPaneSplitter;
	CrySearchArrayCtrl mPeInformationCtrl;
	CrySearchArrayCtrl mSections;
	CrySearchArrayCtrl mDotNetInformation;
	
	void ToolBar(Bar& pBar);
	void SectionsListRightClick(Bar& pBar);
	void DotNetSectionsListRightClick(Bar& pBar);

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
