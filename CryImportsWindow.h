#ifndef _CrySearch_CryImportsWindow_h_
#define _CrySearch_CryImportsWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"
#include "CrySearchArrayCtrl.h"

class CryImportsWindow sealed : public ParentCtrl
{
private:
	ArrayCtrl mModulesList;
	CrySearchArrayCtrl mFunctionsList;
	Splitter mControlSplitter;
	
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

extern Win32ModuleInformation* FindModuleInVector(const char* modName);

#endif
