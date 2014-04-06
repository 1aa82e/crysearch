#ifndef _CrySearch_CryImportsWindow_h_
#define _CrySearch_CryImportsWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"
#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"

class CryImportsWindow sealed : public ParentCtrl
{
private:
	ToolBar mToolStrip;
	ArrayCtrl mModulesList;
	CrySearchArrayCtrl mFunctionsList;
	Splitter mControlSplitter;
	Label mModulesDescriptorLabel;
	VirtualDropList mModulesDropList;
	
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
	void ModuleRedraw();
};

extern const Win32ModuleInformation* FindModuleInVector(const char* modName);

#endif
