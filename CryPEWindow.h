#ifndef _CrySearch_CryPEWindow_h_
#define _CrySearch_CryPEWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"

// Represents the portable executable format information window. When a process is opened, its
// PE header is analyzed. Some information inside it is shown in this window. Information about
// image sections, .NET header and .NET sections is displayed as well.
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
	void SectionsListSelectionChanged();
	
	typedef CryPEWindow CLASSNAME;
public:
	CryPEWindow();
	~CryPEWindow();
	
	void Initialize();
	void ClearList();
};

#endif
