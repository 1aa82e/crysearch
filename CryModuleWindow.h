#ifndef _CrySearch_CryModuleWindow_h_
#define _CrySearch_CryModuleWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"

class CryModuleWindow sealed : public ParentCtrl
{
private:
	ToolBar tBar;
	ArrayCtrl mModules;
	
	void ToolBar(Bar& pBar);
	void ModuleListRightClick(Bar& pBar);
	
	void LoadLibraryButtonClicked();
	void UnloadModule();
	void RefreshModulesList();
	void DumpModuleButton();
	void DumpModuleSubMenu(Bar& pBar);
	void RestorePEHeader();
	void HideModule();
	void OpenModulePathInExplorer();
	void DumpAllModulesButton();
	void DumpModuleSectionButton();
	
	typedef CryModuleWindow CLASSNAME;
public:
	CryModuleWindow();
	~CryModuleWindow();
	
	void Initialize();
	void ClearList();
};

#endif
