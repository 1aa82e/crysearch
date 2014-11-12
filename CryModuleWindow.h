#ifndef _CrySearch_CryModuleWindow_h_
#define _CrySearch_CryModuleWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"
#include "CrySearchArrayCtrl.h"

class CryModuleWindow : public ParentCtrl
{
private:
	ToolBar tBar;
	CrySearchArrayCtrl mModules;
	
	void ToolBar(Bar& pBar);
	void ModuleListRightClick(Bar& pBar);
	
	void LoadLibraryButtonClicked();
	void LoadLibraryThread(String pLibrary);
	void LoadLibraryAsyncDone(BOOL result);
	void LoadLibraryAsyncDoneThreadSafe(BOOL result);
	void UnloadModule();
	void UnloadModuleThread(const SIZE_T pBase);
	void UnloadModuleAsyncDone(const SIZE_T pBase);
	void UnloadModuleAsyncDoneThreadSafe(const SIZE_T pBase);
	void RefreshModulesList();
	void DumpModuleButton(const SIZE_T pluginBase);
	void DumpModuleButtonSubMenu(Bar& pBar);
	void DumpModuleSubMenu(Bar& pBar);
	void RestorePEHeader();
	void HideModule();
	void OpenModulePathInExplorer();
	void DumpAllModulesButton();
	void DumpModuleSectionButton();
	
	Callback1<BOOL> InjectionDone;
	Callback1<SIZE_T> UnloadDone;
	
	typedef CryModuleWindow CLASSNAME;
public:
	CryModuleWindow();
	~CryModuleWindow();
	
	void Initialize();
	void ClearList();
};

#endif
