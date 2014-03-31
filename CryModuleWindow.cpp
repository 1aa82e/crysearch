#include "CryModuleWindow.h"
#include "CryDumpModuleSectionWindow.h"
#include "ImlProvider.h"

#include <Psapi.h>
#include <Shlwapi.h>

String GetName(const int index)
{
	return LoadedModulesList[index].ModuleName;
}

String GetBaseAddress(const int index)
{
#ifdef _WIN64
	return Format("%llX", (__int64)LoadedModulesList[index].BaseAddress);
#else
	return Format("%lX", (int)LoadedModulesList[index].BaseAddress);
#endif
}

String GetLength(const int index)
{
#ifdef _WIN64
	return Format("%llX", LoadedModulesList[index].Length);
#else
	return Format("%lX", LoadedModulesList[index].Length);
#endif
}

CryModuleWindow::CryModuleWindow()
{
	this->AddFrame(this->tBar);
	this->tBar.Set(THISBACK(ToolBar));
	
	this->mModules.AddRowNumColumn("Name").SetConvert(Single<IndexBasedValueConvert<GetName>>());
	this->mModules.AddRowNumColumn("Base Address").SetConvert(Single<IndexBasedValueConvert<GetBaseAddress>>());
	this->mModules.AddRowNumColumn("Size").SetConvert(Single<IndexBasedValueConvert<GetLength>>());
	this->mModules.WhenBar = THISBACK(ModuleListRightClick);
	
	*this << this->mModules.SizePos();
}

CryModuleWindow::~CryModuleWindow()
{
	
}

void CryModuleWindow::ToolBar(Bar& pBar)
{
	pBar.Add("Refresh module list", CrySearchIml::RefreshButtonSmall(), THISBACK(RefreshModulesList));
	pBar.Separator();
	pBar.Add("Dump all modules", CrySearchIml::DumpAllModulesSmall(), THISBACK(DumpAllModulesButton));
	pBar.Add("Load Library", CrySearchIml::LoadLibrarySmall(), THISBACK(LoadLibraryButtonClicked));
}

void CryModuleWindow::ModuleListRightClick(Bar& pBar)
{
	const int modRow = this->mModules.GetCursor();
	if (modRow >= 0 && LoadedModulesList.GetCount() > 0)
	{
		pBar.Add("Dump module", CrySearchIml::DumpModuleSmall(), THISBACK(DumpModuleSubMenu));
		pBar.Add("Restore Headers", CrySearchIml::RestorePEHeadersSmall(), THISBACK(RestorePEHeader));
		pBar.Add("View in Explorer", THISBACK(OpenModulePathInExplorer));
		pBar.Separator();
		pBar.Add("Hide module", THISBACK(HideModule));
		pBar.Add("Unload module", THISBACK(UnloadModule));
	}
}

void CryModuleWindow::DumpModuleSubMenu(Bar& pBar)
{
	pBar.Add("Full", THISBACK(DumpModuleButton));
	pBar.Add("Section", THISBACK(DumpModuleSectionButton));
}

void CryModuleWindow::OpenModulePathInExplorer()
{
	char folder[MAX_PATH];
	if (!GetModuleFileNameEx(mMemoryScanner->GetHandle(), (HMODULE)LoadedModulesList[this->mModules.GetCursor()].BaseAddress, folder, MAX_PATH))
	{
		Prompt("Module Error", CtrlImg::error(), "The working directory of the selected module could not be retrieved!", "OK");
		return;
	}
	
	// Open retrieved path in explorer.
	PathRemoveFileSpec(folder);
	ShellExecute(this->GetHWND(), "explore", folder, NULL, NULL, SW_SHOWNORMAL);
}

void CryModuleWindow::UnloadModule()
{
	const SIZE_T oldBase = LoadedModulesList[this->mModules.GetCursor()].BaseAddress;
	
	mPeInstance->UnloadLibraryExternal(oldBase);
	this->RefreshModulesList();
	
	for (int i = 0; i < LoadedModulesList.GetCount(); i++)
	{
		if (LoadedModulesList[i].BaseAddress == oldBase)
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
		if (mPeInstance->LoadLibraryExternal(fs->Get()))
		{
			PromptOK("Library succesfully loaded!");
		}
		else
		{
			Prompt("Load Error", CtrlImg::error(), "The library was not loaded succesfully!", "OK");
		}
		
		this->RefreshModulesList();
	}
	
	delete fs;
}

void CryModuleWindow::DumpAllModulesButton()
{
	FileSel* fs = new FileSel();
	if (fs->ExecuteSelectDir("Select directory"))
	{
		bool error = false;
		String dir = fs->Get();
		for (int i = 0; i < LoadedModulesList.GetCount(); ++i)
		{
			const Win32ModuleInformation& mod = LoadedModulesList[i];
			if (!mPeInstance->DumpProcessModule(AppendFileName(dir, mod.ModuleName), mod))
			{
				error = true;
			}
		}
		
		// If an error occured, display message box once at the end of the function.
		if (error)
		{
			Prompt("Dumping Error", CtrlImg::error(), "One or more modules failed to dump. Check the contents of the selected directory to see which.", "OK");
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
	CryDumpModuleSectionWindow* cdmsw = new CryDumpModuleSectionWindow(this->mModules.GetCursor());
	cdmsw->Execute();
	delete cdmsw;
}

void CryModuleWindow::DumpModuleButton()
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
		if (mPeInstance->DumpProcessModule(fs->Get(), LoadedModulesList[row]))
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
	EnumerateModules(mMemoryScanner->GetHandle(), mMemoryScanner->GetProcessId());
	
	this->mModules.SetVirtualCount(LoadedModulesList.GetCount());
}

void CryModuleWindow::RestorePEHeader()
{
	const int modRow = this->mModules.GetCursor();

	FileSel* fs = new FileSel();
	fs->Types("Executable files\t*.exe\nDynamic Link Libraries\t*.dll\nWindows Drivers\t*.sys");

	// Try to get the working directory of the desired module first.
	char folder[MAX_PATH];
	if (GetModuleFileNameEx(mMemoryScanner->GetHandle(), (HMODULE)LoadedModulesList[this->mModules.GetCursor()].BaseAddress, folder, MAX_PATH))
	{
		// Remove the file specification from the path and use it as default path in the FileSel.
		PathRemoveFileSpec(folder);
		fs->ActiveDir(folder);
	}
	
	// Open the FileSel window. If a file was selected, attempt to restore it.
	if (fs->ExecuteOpen("Select restore file"))
	{
		if (mPeInstance->RestorePEHeaderFromFile(fs->Get(), LoadedModulesList[modRow]))
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
	if (mPeInstance->HideModuleFromProcess(LoadedModulesList[this->mModules.GetCursor()]))
	{
		PromptOK("Module succesfully hidden!");
		this->RefreshModulesList();
		return;
	}
	else
	{
		Prompt("Hide Error", CtrlImg::error(), "Failed to hide the module! Either the module selected module was not succesfully found"\
			", target process writes failed or the nessecary data could not be retrieved. Try again or try another module.", "OK");
		this->RefreshModulesList();
	}
}

void CryModuleWindow::Initialize()
{
	this->RefreshModulesList();
}

void CryModuleWindow::ClearList()
{
	LoadedModulesList.Clear();
	this->mModules.SetVirtualCount(0);
}