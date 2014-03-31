#ifndef _CrySearch_CryPEWindow_h_
#define _CrySearch_CryPEWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"

#pragma warning(disable : 4005)

class CryPEWindow sealed : public ParentCtrl
{
private:
	ToolBar tBar;
	Splitter mSplitter;
	ArrayCtrl mPeInformationCtrl;
	ArrayCtrl mSections;
	
	void ToolBar(Bar& pBar);
	void SectionsListRightClick(Bar& pBar);

	void DumpSection();
	
	typedef CryPEWindow CLASSNAME;
public:
	CryPEWindow();
	~CryPEWindow();
	
	void Initialize();
	void ClearList();
};

#endif
