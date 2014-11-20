#include "CryImportsWindow.h"
#include "BackendGlobalDef.h"
#include "CryPlaceIATHookWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// The master index is the index of the selected module in the list of impor entries. Depending on this index, the functions are displayed.
int MasterIndex;

String GetModule(const int index)
{
	return LoadedProcessPEInformation.ImportAddressTable.GetKey(index).ModuleName;
}

String GetFunction(const int index)
{
	return (LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex))[index]).FunctionName;
}

String GetHint(const int index)
{
	const ImportAddressTableEntry& current = LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex))[index];
	return current.Hint ? Format("%X", current.Hint) : Format("Ord (%i)", (int)current.Ordinal);
}

String GetVirtualAddress(const int index)
{
#ifdef _WIN64
	return Format("%llX", (__int64)LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex))[index].VirtualAddress);
#else
	return Format("%lX", (int)LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex))[index].VirtualAddress);
#endif
}

String GetModuleStringRepresentation(const int index)
{
#ifdef _WIN64
	return Format("%llX - %s", (__int64)(*mModuleManager)[index].BaseAddress, (*mModuleManager)[index].ModuleName);
#else
	return Format("%lX - %s", (int)(*mModuleManager)[index].BaseAddress, (*mModuleManager)[index].ModuleName);
#endif
}

CryImportsWindow::CryImportsWindow()
{
	this->AddFrame(mToolStrip);
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	this->mModulesList.CryAddRowNumColumn("Module").SetConvert(Single<IndexBasedValueConvert<GetModule>>());
	this->mFunctionsList.CryAddRowNumColumn("Function", 60).SetConvert(Single<IndexBasedValueConvert<GetFunction>>());
	this->mFunctionsList.CryAddRowNumColumn("Hint", 15).SetConvert(Single<IndexBasedValueConvert<GetHint>>());
	this->mFunctionsList.CryAddRowNumColumn("Virtual Address", 25).SetConvert(Single<IndexBasedValueConvert<GetVirtualAddress>>());
	
	this->mFunctionsList.WhenBar = THISBACK(FunctionListRightClick);
	
	this->mModulesList.WhenSel = THISBACK(ModuleChanged);

	*this << this->mControlSplitter.Horz(this->mModulesList.SizePos(), this->mFunctionsList.SizePos());

	this->mControlSplitter.SetMinPixels(0, 150);
	this->mControlSplitter.SetMinPixels(1, 300);
	this->mControlSplitter.SetPos(3500);

	this->mModulesDropList.SetConvert(Single<IndexBasedValueConvert<GetModuleStringRepresentation>>());
	this->mModulesDropList.WhenDrop = THISBACK(ModulesDropped);
	this->mModulesDropList.WhenAction = THISBACK(ModulesSelected);
}

CryImportsWindow::~CryImportsWindow()
{
	
}

void CryImportsWindow::ToolStrip(Bar& pBar)
{
	pBar.Add(this->mModulesDescriptorLabel.SetLabel("Module: "));
	pBar.Add(this->mModulesDropList, 200);
	pBar.Separator();
	pBar.Add("Refresh", CrySearchIml::RefreshButtonSmall(), THISBACK(RefreshImports));
}

void CryImportsWindow::ModulesDropped()
{
	// Refresh modules before dropping the list.
	mModuleManager->Initialize();
	this->mModulesDropList.SetCount(mModuleManager->GetModuleCount());
}

void CryImportsWindow::ModulesSelected()
{
	const int cursor = this->mModulesDropList.GetIndex();
	const int modCount = mModuleManager->GetModuleCount();
	if (cursor >= 0 && modCount > 0)
	{
		// Alter base address to match the module's one, get infos and quickly restore exe base address.
		mPeInstance->SetBaseAddress((*mModuleManager)[cursor].BaseAddress);
		this->RefreshImports();
		mPeInstance->SetBaseAddress(mModuleManager->GetBaseAddress());
		
		// Set the new index of the drop list to the newly selected module.
		this->mModulesDropList.SetIndex(cursor);
	}
}

void CryImportsWindow::FunctionListRightClick(Bar& pBar)
{
	if (this->mFunctionsList.GetCount() > 0 && this->mFunctionsList.GetCursor() >= 0)
	{
		if (LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex)).At(this->mFunctionsList.GetCursor()).Flag == IAT_FLAG_HOOKED)
		{
			pBar.Add("Restore Address", THISBACK(RestoreIATFunction));
		}
		else
		{
			pBar.Add("Place Hook", CrySearchIml::PlaceHookSmall(), THISBACK(PlaceHookOnIATFunction));
		}
	}
}

void CryImportsWindow::RestoreIATFunction()
{
	const ImportTableDescriptor& key = LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex);
	const Win32ModuleInformation* const masterMod = &(*mModuleManager)[this->mModulesDropList.GetIndex()];
	const ImportAddressTableEntry& entry = LoadedProcessPEInformation.ImportAddressTable.Get(key)[this->mFunctionsList.GetCursor()];

	// Set the base address to the correct module.
	mPeInstance->SetBaseAddress((*mModuleManager)[this->mModulesDropList.GetIndex()].BaseAddress);
	
	if (key.LogicalBaseAddress)
	{
		mPeInstance->RestoreExportTableAddressImport(masterMod, key.LogicalBaseAddress, entry.Ordinal ? (char*)entry.Ordinal : entry.FunctionName, entry.Ordinal);
	}
	else
	{
		mPeInstance->RestoreExportTableAddressImport(masterMod, mModuleManager->FindModule(LoadedProcessPEInformation.ImportAddressTable.GetKey(this->mModulesList.GetCursor()).ModuleName)->BaseAddress, entry.Ordinal ? (char*)entry.Ordinal : entry.FunctionName, entry.Ordinal);
	}
	
	this->RefreshImports();
}

void CryImportsWindow::PlaceHookOnIATFunction()
{
	const ImportTableDescriptor& masterKey = LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex);
	const Win32ModuleInformation* const masterMod = &(*mModuleManager)[this->mModulesDropList.GetIndex()];
	const ImportAddressTableEntry& entry = LoadedProcessPEInformation.ImportAddressTable.Get(masterKey).At(this->mFunctionsList.GetCursor());
	const char* param = NULL;
	CryPlaceIATHookWindow* cpthw = NULL;
	
	// Check for the EAT address associated to the function. If the EAT address is not found, the address cannot be restored later.
	if (entry.Flag == IAT_FLAG_NOT_FOUND && !Prompt("I need your confirmation", CtrlImg::exclamation(),
		"The address of this function could not be found in the export table of the module. Therefore the address cannot be restored. Are you sure you want to place a hook on this function?"
		, "Yes", "No"))
	{
		return;
	}
	
	// Set the base address to the correct module.
	mPeInstance->SetBaseAddress(masterMod->BaseAddress);

	// Ordinal import or named import? Differentiate here, the backend will take care of the rest.
	if (entry.Ordinal == 0)
	{
		param = entry.FunctionName;
		cpthw = new CryPlaceIATHookWindow(masterMod, param, false, CrySearchIml::PlaceHookSmall());
	}
	else
	{
		param = (char*)entry.Ordinal;
		cpthw = new CryPlaceIATHookWindow(masterMod, param, true, CrySearchIml::PlaceHookSmall());
	}
	
	cpthw->Execute();
	delete cpthw;
	
	// Reload imports to view the hooked import.
	this->RefreshImports();
}

void CryImportsWindow::DataRetrievalDone()
{
	if (mModuleManager->GetModuleCount() > 0)
	{
		mPeInstance->SetBaseAddress(mModuleManager->GetBaseAddress());
	}
	else
	{
		mPeInstance->SetBaseAddress(0);
	}
}

void CryImportsWindow::ModuleRedraw()
{
	this->ModuleChanged();
}

void CryImportsWindow::ModuleChanged()
{
	MasterIndex = this->mModulesList.GetCursor();
	const int virtualcount = MasterIndex >= 0 && LoadedProcessPEInformation.ImportAddressTable.GetCount() > 0 ? LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex)).GetCount() : 0;
	this->mFunctionsList.SetVirtualCount(virtualcount);
	
	// The import table should contain something.
	if (virtualcount)
	{
		// Iterate imported functions for the currently selected module and draw hooked functions in red.
		const Vector<ImportAddressTableEntry>& list = LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex));
		for (int i = 0; i < list.GetCount(); i++)
		{
			if (list[i].Flag == IAT_FLAG_HOOKED)
			{
				this->mFunctionsList.SetRowDisplay(i, RedDisplayDrawInstance);
			}
			else
			{
				this->mFunctionsList.SetRowDisplay(i, StdDisplay());
			}
		}
	}
}

void CryImportsWindow::RefreshImports()
{
	// If a module is selected, refresh the imports of this module. Otherwise refresh the exe imports.
	const int cursor = this->mModulesDropList.GetIndex();
	if (cursor >= 0 && mModuleManager->GetModuleCount() > 0)
	{
		mPeInstance->SetBaseAddress((*mModuleManager)[cursor].BaseAddress);
	}
	else
	{
		mPeInstance->SetBaseAddress(0);
	}
	
	LoadedProcessPEInformation.ClearImportTable();
	this->Initialize();
}

void CryImportsWindow::Initialize()
{
	const int modCount = mModuleManager->GetModuleCount();
	mPeInstance->GetImportAddressTable();
	this->mModulesDropList.SetCount(modCount);
	const int cursor = this->mModulesDropList.GetIndex();
	if (modCount > 0)
	{
		if (cursor >= 0)
		{
			this->mModulesDropList.SetIndex(cursor);
		}
		else
		{
			this->mModulesDropList.SetIndex(0);
		}
	}
	
	// Make sure the base address is correct again.
	this->DataRetrievalDone();
	
	// If the IAT could not be loaded, and is empty, do not trigger the event. This will crash CrySearch.
	if (LoadedProcessPEInformation.ImportAddressTable.GetCount())
	{
		this->mModulesList.SetVirtualCount(LoadedProcessPEInformation.ImportAddressTable.GetCount());
		this->mModulesList.SetCursor(0);
		
		// Trigger the event to load the functions inside an imported module.
		this->ModuleChanged();
	}
}

// Just in case, a function that clears everything in this window to avoid problems.
void CryImportsWindow::ClearList()
{
	this->mModulesList.SetVirtualCount(0);
	this->mFunctionsList.SetVirtualCount(0);
	this->mModulesDropList.SetCount(0);
	LoadedProcessPEInformation.ClearImportTable();
}