#include "CryModuleWindow.h"
#include "CryDumpModuleSectionWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

#include <Psapi.h>
#include <Shlwapi.h>

String GetName(const int index)
{
	return mModuleManager->GetModuleFilename((*mModuleManager)[index].BaseAddress);
}

String GetBaseAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((__int64)(*mModuleManager)[index].BaseAddress);
#else
	return FormatHexadecimalIntSpecial((int)(*mModuleManager)[index].BaseAddress);
#endif
}

String GetLength(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((*mModuleManager)[index].Length);
#else
	return FormatHexadecimalIntSpecial((*mModuleManager)[index].Length);
#endif
}

CryModuleWindow::CryModuleWindow()
{
	this->AddFrame(this->tBar);
	this->tBar.Set(THISBACK(ToolBar));
	
	this->mModules.CryAddRowNumColumn("Name", 50).SetConvert(Single<IndexBasedValueConvert<GetName>>());
	this->mModules.CryAddRowNumColumn("Base Address", 25).SetConvert(Single<IndexBasedValueConvert<GetBaseAddress>>());
	this->mModules.CryAddRowNumColumn("Size", 25).SetConvert(Single<IndexBasedValueConvert<GetLength>>());
	this->mModules.WhenBar = THISBACK(ModuleListRightClick);
	
	*this << this->mModules.SizePos();
	
	this->InjectionDone = THISBACK(LoadLibraryAsyncDone);
	this->UnloadDone = THISBACK(UnloadModuleAsyncDone);
}

CryModuleWindow::~CryModuleWindow()
{
	
}

void CryModuleWindow::ToolBar(Bar& pBar)
{
	pBar.Add("Refresh module list", CrySearchIml::RefreshButtonSmall(), THISBACK(RefreshModulesList));
	pBar.Separator();
	pBar.Add("Dump all modules", CrySearchIml::DumpAllModulesSmall(), THISBACK(DumpAllModulesButton));
	pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Load Library", CrySearchIml::LoadLibrarySmall(), THISBACK(LoadLibraryButtonClicked));
	pBar.ToolGapRight();
	pBar.Add(this->mModulesCount.SetAlign(ALIGN_RIGHT), 150);
}

void CryModuleWindow::ModuleListRightClick(Bar& pBar)
{
	const int modRow = this->mModules.GetCursor();
	const int modCount = mModuleManager->GetModuleCount();
	if (modRow >= 0 && modCount > 0)
	{
		pBar.Add("Dump module", CrySearchIml::DumpModuleSmall(), THISBACK(DumpModuleSubMenu));
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Restore Headers", CrySearchIml::RestorePEHeadersSmall(), THISBACK(RestorePEHeader));
		pBar.Add("View in Explorer", THISBACK(OpenModulePathInExplorer));
		pBar.Separator();
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Hide module", THISBACK(HideModule));
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Unload module", THISBACK(UnloadModule));
	}
}

void CryModuleWindow::DumpModuleSubMenu(Bar& pBar)
{
	pBar.Add("Full", THISBACK(DumpModuleButtonSubMenu));
	pBar.Add("Section", THISBACK(DumpModuleSectionButton));
}

void CryModuleWindow::DumpModuleButtonSubMenu(Bar& pBar)
{
	// Retrieve all loaded dump engine plugins.
	Vector<CrySearchPlugin> dumpers;
	mPluginSystem->GetPluginsByType(CRYPLUGIN_DUMPER, dumpers);
	
	// If there are no dumpers available, display a disabled message button.
	if (!dumpers.GetCount())
	{
		pBar.Add(false, "No Dumpers available", THISBACK1(DumpModuleButton, NULL));
		return;
	}
	
	// Still here, so add menus for the dumpers.
	for (int i = 0; i < dumpers.GetCount(); ++i)
	{
		const CrySearchPlugin& plugin = dumpers[i];
		pBar.Add(plugin.PluginHeader->PluginName, THISBACK1(DumpModuleButton, (SIZE_T)plugin.BaseAddress));
	}
}

void CryModuleWindow::OpenModulePathInExplorer()
{
	// Execute the working directory of the selected module in explorer.
	char folder[MAX_PATH];
	if (!GetModuleFileNameEx(mMemoryScanner->GetHandle(), (HMODULE)(*mModuleManager)[this->mModules.GetCursor()].BaseAddress, folder, MAX_PATH))
	{
		Prompt("Module Error", CtrlImg::error(), "The working directory of the selected module could not be retrieved!", "OK");
	}

	// Open retrieved path in explorer.
	PathRemoveFileSpec(folder);
	ShellExecute(this->GetHWND(), "explore", folder, NULL, NULL, SW_SHOWNORMAL);
}

void CryModuleWindow::UnloadModule()
{
	const SIZE_T oldBase = (*mModuleManager)[this->mModules.GetCursor()].BaseAddress;
	const char* pName = NULL;
	
	// The module that was unloaded may be a CrySearch plugin. Make sure it is fixed up.
	if (pName = mPluginSystem->IsPluginLoaded((HMODULE)oldBase))
	{
		// A plugin is about to be silently unloaded. Remove it from the list.
		if (mPluginSystem->UnloadPlugin(pName))
		{
			this->RefreshModulesList();
			PromptOK("Module succesfully unloaded!");
		}
		else
		{
			Prompt("Unload Error", CtrlImg::error(), "The module could not be unloaded!", "OK");
		}
	}
	else
	{
		// Module was not a plugin, use default procedure.
		threadPool & THISBACK1(UnloadModuleThread, oldBase);
	}
}

void CryModuleWindow::UnloadModuleThread(const SIZE_T pBase)
{
	mPeInstance->UnloadLibraryExternal(pBase);
	this->UnloadDone(pBase);
}

void CryModuleWindow::UnloadModuleAsyncDone(const SIZE_T pBase)
{
	PostCallback(THISBACK1(UnloadModuleAsyncDoneThreadSafe, pBase));
}

void CryModuleWindow::UnloadModuleAsyncDoneThreadSafe(const SIZE_T pBase)
{
	// Check whether the module was actually unloaded. (not included in refresh)
	this->RefreshModulesList();
	const int modCount = mModuleManager->GetModuleCount();
	for (int i = 0; i < modCount; i++)
	{
		if ((*mModuleManager)[i].BaseAddress == pBase)
		{
			Prompt("Unload Error", CtrlImg::error(), "The module could not be unloaded!", "OK");
			return;
		}
	}
	
	// Module succesfully unloaded.
	PromptOK("Module succesfully unloaded!");
}

void CryModuleWindow::LoadLibraryButtonClicked()
{
	FileSel* fs = new FileSel();
	fs->Types("Dynamic Link Library files\t*.dll");
	
	if (fs->ExecuteOpen("Select library file..."))
	{
		// Execute the library injection asynchronously.
		threadPool & THISBACK1(LoadLibraryThread, fs->Get());		
	}
	
	delete fs;
}

void CryModuleWindow::LoadLibraryThread(String pLibrary)
{
	BOOL result = FALSE;
	
	// Check which injection method is selected. Call the correct one accordingly.
	const int method = SettingsFile::GetInstance()->GetLibraryInjectionMethod();
	if (method == INJECTION_METHOD_CRT)
	{
		result = mPeInstance->LoadLibraryExternal(pLibrary);
	}
	else if (method == INJECTION_METHOD_HIJACKTHREAD)
	{
		// Randomly select thread in target process to hijack.
		const int threadcount = mThreadsList.GetCount();
		HANDLE hThread = NULL;
		for (int i = 0; i < threadcount || hThread == NULL; ++i)
		{
			hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, mThreadsList[i].ThreadIdentifier);
		}
		
		// Start the injection process. The handle will be closed by the injection function.
		result = mPeInstance->LoadLibraryExternalHijack(pLibrary, hThread);
	}
		
	// The result can be passed into the asynchronous completion callback.
	this->InjectionDone(result);
}

void CryModuleWindow::LoadLibraryAsyncDone(BOOL result)
{
	PostCallback(THISBACK1(LoadLibraryAsyncDoneThreadSafe, result));
}

void CryModuleWindow::LoadLibraryAsyncDoneThreadSafe(BOOL result)
{
	if (result)
	{
		PromptOK("Library succesfully loaded!");
	}
	else
	{
		Prompt("Load Error", CtrlImg::error(), "The library was not loaded succesfully!", "OK");
	}
	
	this->RefreshModulesList();
}

void CryModuleWindow::DumpAllModulesButton()
{
	FileSel* fs = new FileSel();
	if (fs->ExecuteSelectDir("Select directory"))
	{
		bool error = false;
		bool nodumper = false;
		String dir = fs->Get();
		
#ifdef _WIN64
		const int modCount = mModuleManager->GetModuleCount();
		if (mMemoryScanner->IsX86Process())
		{
			CreateModuleDumpProc32 pCMDP = (CreateModuleDumpProc32)GetProcAddress(mPluginSystem->GetDefaultDumperEnginePlugin(), "CreateModuleDump32");
			if (!pCMDP)
			{
				nodumper = true;
			}
			
			// Dump all loaded modules.
			for (int i = 0; i < modCount; ++i)
			{
				const Win32ModuleInformation& mod = (*mModuleManager)[i];
				if (!pCMDP || !pCMDP(mMemoryScanner->GetHandle(), (void*)mod.BaseAddress, (DWORD)mod.Length, AppendFileName(dir, mModuleManager->GetModuleFilename(mod.BaseAddress))))
				{
					error = true;
				}
			}
		}
		else
		{
			CreateModuleDumpProc64 pCMDP = (CreateModuleDumpProc64)GetProcAddress(mPluginSystem->GetDefaultDumperEnginePlugin(), "CreateModuleDump64");
			if (!pCMDP)
			{
				nodumper = true;
			}
			
			// Dump all loaded modules.
			for (int i = 0; i < modCount; ++i)
			{
				const Win32ModuleInformation& mod = (*mModuleManager)[i];
				if (!pCMDP || !pCMDP(mMemoryScanner->GetHandle(), (void*)mod.BaseAddress, (DWORD)mod.Length, AppendFileName(dir, mModuleManager->GetModuleFilename(mod.BaseAddress))))
				{
					error = true;
				}
			}
		}
#else
		CreateModuleDumpProc32 pCMDP = (CreateModuleDumpProc32)GetProcAddress(mPluginSystem->GetDefaultDumperEnginePlugin(), "CreateModuleDump32");
		if (!pCMDP)
		{
			nodumper = true;
		}
		
		// Dump all loaded modules.
		const int modCount = mModuleManager->GetModuleCount();
		for (int i = 0; i < modCount; ++i)
		{
			const Win32ModuleInformation& mod = (*mModuleManager)[i];
			if (!pCMDP || !pCMDP(mMemoryScanner->GetHandle(), (void*)mod.BaseAddress, (DWORD)mod.Length, AppendFileName(dir, mModuleManager->GetModuleFilename(mod.BaseAddress))))
			{
				error = true;
			}
		}
#endif
		
		// If an error occured, display message box once at the end of the function.
		if (error)
		{
			if (nodumper)
			{
				Prompt("Dumping Error", CtrlImg::error(), "The dumping failed because there is no dumper available.", "OK");
			}
			else
			{
				Prompt("Dumping Error", CtrlImg::error(), "One or more modules failed to dump. Check the contents of the selected directory to see which.", "OK");
			}
		}
		else
		{
			PromptOK("Dump succeeded!");
		}
	}
	
	delete fs;
}

void CryModuleWindow::DumpModuleSectionButton()
{
	CryDumpModuleSectionWindow* cdmsw = new CryDumpModuleSectionWindow(this->mModules.GetCursor(), CrySearchIml::DumpModuleSmall());
	cdmsw->Execute();
	delete cdmsw;
}

void CryModuleWindow::DumpModuleButton(const SIZE_T pluginBase)
{
	FileSel* fs = new FileSel();
	
	const int row = this->mModules.GetCursor();
	if (row == 0)
	{
		fs->Types("Executable files\t*.exe\nCommand prompt executable files\t*.com\nBinary files\t*.bin");
	}
	else
	{
		fs->Types("Dynamic Link Library files\t*.dll\nObject Control Extension files\t*.ocx\nBinary files\t*.bin");
	}
	
	if (fs->ExecuteSaveAs("Select dump location"))
	{
		// If the file already exists it should be deleted first.
		DeleteFile(fs->Get());
		
		const Win32ModuleInformation& toDump = (*mModuleManager)[row];
		
#ifdef _WIN64
		BOOL result = FALSE;
		if (mMemoryScanner->IsX86Process())
		{
			CreateModuleDumpProc32 pCMDP = (CreateModuleDumpProc32)GetProcAddress((HMODULE)pluginBase, "CreateModuleDump32");
			result = pCMDP && pCMDP(mMemoryScanner->GetHandle(), (void*)toDump.BaseAddress, (DWORD)toDump.Length, fs->Get());
		}
		else
		{
			CreateModuleDumpProc64 pCMDP = (CreateModuleDumpProc64)GetProcAddress((HMODULE)pluginBase, "CreateModuleDump64");
			result = pCMDP && pCMDP(mMemoryScanner->GetHandle(), (void*)toDump.BaseAddress, (DWORD)toDump.Length, fs->Get());			
		}
		
#else
		CreateModuleDumpProc32 pCMDP = (CreateModuleDumpProc32)GetProcAddress((HMODULE)pluginBase, "CreateModuleDump32");
		BOOL result = pCMDP && pCMDP(mMemoryScanner->GetHandle(), (void*)toDump.BaseAddress, (DWORD)toDump.Length, fs->Get());
#endif
		
		if (result)
		{
			PromptOK("Dump succeeded!");
		}
		else
		{
			Prompt("Dumping Error", CtrlImg::error(), "Failed to dump the module. Either reading memory or writing the file failed.", "OK");
		}
	}
	
	delete fs;
}

void CryModuleWindow::RefreshModulesList()
{
	mModuleManager->Initialize();
	const int mCount = mModuleManager->GetModuleCount();
	this->mModules.SetVirtualCount(mCount);
	this->mModulesCount.SetLabel(Format("Total %i modules", mCount));
}

void CryModuleWindow::RestorePEHeader()
{
	const int modRow = this->mModules.GetCursor();

	FileSel* fs = new FileSel();
	fs->Types("Executable files\t*.exe\nDynamic Link Libraries\t*.dll\nWindows Drivers\t*.sys");

	// Try to get the working directory of the desired module first.
	char folder[MAX_PATH];
	if (GetModuleFileNameEx(mMemoryScanner->GetHandle(), (HMODULE)(*mModuleManager)[this->mModules.GetCursor()].BaseAddress, folder, MAX_PATH))
	{
		// Remove the file specification from the path and use it as default path in the FileSel.
		PathRemoveFileSpec(folder);
		fs->ActiveDir(folder);
	}
	
	// Open the FileSel window. If a file was selected, attempt to restore it.
	if (fs->ExecuteOpen("Select restore file"))
	{
		if (mPeInstance->RestorePEHeaderFromFile(fs->Get(), (*mModuleManager)[modRow]))
		{
			PromptOK("Headers succesfully restored!");
		}
		else
		{
			Prompt("Restore Error", CtrlImg::error(), "The headers could not be restored! The input file may not be valid or operating on it failed.", "OK");
		}
	}
	
	delete fs;
}

void CryModuleWindow::HideModule()
{
	if (mPeInstance->HideModuleFromProcess((*mModuleManager)[this->mModules.GetCursor()]))
	{
		this->RefreshModulesList();
		PromptOK("Module succesfully hidden!");
		return;
	}
	else
	{
		this->RefreshModulesList();
		Prompt("Hide Error", CtrlImg::error(), "Failed to hide the module! Either the module selected module was not succesfully found"\
			", target process writes failed or the nessecary data could not be retrieved. Try again or try another module.", "OK");
	}
}

void CryModuleWindow::Initialize()
{
	this->RefreshModulesList();
}

void CryModuleWindow::ClearList()
{
	mModuleManager->ClearModules();
	this->mModules.SetVirtualCount(0);
}

// Updates the toolbar inside this lower pane window instance.
void CryModuleWindow::UpdateToolbar()
{
	this->tBar.Set(THISBACK(ToolBar));
}