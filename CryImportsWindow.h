#ifndef _CrySearch_CryImportsWindow_h_
#define _CrySearch_CryImportsWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"

// Represents the IAT tab page window.
class CryImportsWindow : public ParentCtrl
{
private:
	ToolBar mToolStrip;
	CrySearchArrayCtrl mModulesList;
	CrySearchArrayCtrl mFunctionsList;
	Splitter mControlSplitter;
	Label mModulesDescriptorLabel;
	VirtualDropList mModulesDropList;
	Label mFunctionCount;
	
	void ToolStrip(Bar& pBar);
	
	void ModulesDropped();
	void ModulesSelected();
	void DataRetrievalDone();
	
	void RefreshImports();
	void ModuleChanged();
	void FunctionListRightClick(Bar& pBar);
	void PlaceHookOnIATFunction();
	void RestoreIATFunction();
	
	typedef CryImportsWindow CLASSNAME;
public:
	CryImportsWindow();
	~CryImportsWindow();
	
	void Initialize();
	void ClearList();
	void ModuleRedraw();
	void UpdateToolbar();
};

#endif
