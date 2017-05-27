#include "CryImportsWindow.h"
#include "BackendGlobalDef.h"
#include "CryPlaceIATHookWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// The master index is the index of the selected module in the list of impor entries. Depending on this index, the functions are displayed.
int MasterIndex;

// Retrieves the name of a module by index.
String GetModule(const int index)
{
	return LoadedProcessPEInformation.ImportAddressTable[index].ModuleName;
}

// Retrieves the name of a function inside a module by function index.
String GetFunction(const int index)
{
	return LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList[index].FunctionName;
}

// Retrieves the hint of a function (or ordinal) by index.
String GetHint(const int index)
{
	const ImportAddressTableEntry& current = LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList[index];
	return current.Ordinal ? Format("Ord (%i)", (int)current.Ordinal) : Format("%X", current.Hint);
}

// Retrieves the start address of a function by index.
String GetVirtualAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((__int64)LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList[index].VirtualAddress);
#else
	return FormatHexadecimalIntSpecial((int)LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList[index].VirtualAddress);
#endif
}

// Retrieves the string representation of a module, consisting of name and its start address, by module index.
String GetModuleStringRepresentation(const int index)
{
	const Win32ModuleInformation& mod = (*mModuleManager)[index];
#ifdef _WIN64
	return Format("%llX - %s", (__int64)mod.BaseAddress, mModuleManager->GetModuleFilename(mod.BaseAddress));
#else
	return Format("%lX - %s", (int)mod.BaseAddress, mModuleManager->GetModuleFilename(mod.BaseAddress));
#endif
}

// The CryImportsWindow default constructor.
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

// The CryImportsWindow default destructor.
CryImportsWindow::~CryImportsWindow()
{
	
}

// Populates the imports window tool strip.
void CryImportsWindow::ToolStrip(Bar& pBar)
{
	pBar.Add(this->mModulesDescriptorLabel.SetLabel("Module: "));
	pBar.Add(this->mModulesDropList, 200);
	pBar.Separator();
	pBar.Add("Refresh", CrySearchIml::RefreshButtonSmall(), THISBACK(RefreshImports));
	pBar.ToolGapRight();
	pBar.Add(this->mFunctionCount.SetAlign(ALIGN_RIGHT), 150);
}

// Executed when the drop list containing modules is dropped; it populates the drop list before it becomes visible.
void CryImportsWindow::ModulesDropped()
{
	// Refresh modules before dropping the list.
	mModuleManager->Initialize();
	
#ifdef _WIN64
	// The user may want to hide the non-wow64 modules. If so, we need to remove several things from the vector.
	if (mMemoryScanner->IsX86Process() && SettingsFile::GetInstance()->GetHideNonWow64Modules())
	{
		mModuleManager->RemoveNonWow64Modules();
	}
#endif

	// Set the user interface to match the modules.
	this->mModulesDropList.SetCount(mModuleManager->GetModuleCount());
}

// Executed when the user has selected a module from the drop list.
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

// Executed when the user right-clicks the list of functions.
void CryImportsWindow::FunctionListRightClick(Bar& pBar)
{
	if (this->mFunctionsList.GetCount() > 0 && this->mFunctionsList.GetCursor() >= 0)
	{
		if (LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList[this->mFunctionsList.GetCursor()].Flag == IAT_FLAG_HOOKED)
		{
			pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Restore Address", THISBACK(RestoreIATFunction));
		}
		else
		{
			pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Place Hook", CrySearchIml::PlaceHookSmall(), THISBACK(PlaceHookOnIATFunction));
		}
	}
}

// Restores the original address from a function in the import table, using the address from the designated export table.
void CryImportsWindow::RestoreIATFunction()
{
	// In many cases, a function is colored red because an error occured while looking up the function address in the export table
	// rather than it being hooked. Trying to restore the original function address may then cause problems.
	if (this->mModulesDropList.GetIndex() < mModuleManager->GetModuleCount())
	{

		const ImportTableDescriptor& key = LoadedProcessPEInformation.ImportAddressTable[MasterIndex];
		const Win32ModuleInformation* const masterMod = &(*mModuleManager)[this->mModulesDropList.GetIndex()];
		const ImportAddressTableEntry& entry = key.FunctionList[this->mFunctionsList.GetCursor()];

		// Set the base address to the correct module.
		mPeInstance->SetBaseAddress((*mModuleManager)[this->mModulesDropList.GetIndex()].BaseAddress);

		if (key.LogicalBaseAddress)
		{
			mPeInstance->RestoreExportTableAddressImport(masterMod, key.LogicalBaseAddress, entry.Ordinal ? (char*)entry.Ordinal : entry.FunctionName.Begin(), entry.Ordinal);
		}
		else
		{
			mPeInstance->RestoreExportTableAddressImport(masterMod, mModuleManager->FindModule(LoadedProcessPEInformation.ImportAddressTable[this->mModulesList.GetCursor()].ModuleName)->BaseAddress, entry.Ordinal ? (char*)entry.Ordinal : entry.FunctionName.Begin(), entry.Ordinal);
		}

		this->RefreshImports();
	}
}

// Replaces the address of a function in the import table with one that was given by the user.
void CryImportsWindow::PlaceHookOnIATFunction()
{
	const ImportTableDescriptor& masterKey = LoadedProcessPEInformation.ImportAddressTable[MasterIndex];
	const Win32ModuleInformation* const masterMod = &(*mModuleManager)[this->mModulesDropList.GetIndex()];
	const ImportAddressTableEntry& entry = masterKey.FunctionList[this->mFunctionsList.GetCursor()];
	const char* param = NULL;
	CryPlaceIATHookWindow* cpthw = NULL;
	SIZE_T newAddress;
	const bool wasOrdinal = (entry.Ordinal != 0);

	// Check for the EAT address associated to the function. If the EAT address is not found, the address cannot be restored later.
	if (entry.Flag == IAT_FLAG_NOT_FOUND && !Prompt("Are you sure?", CtrlImg::exclamation(),
		"The address of this function could not be found in the export table of the module. Therefore the address cannot be restored. Are you sure you want to place a hook on this function?"
		, "Yes", "No"))
	{
		return;
	}
	
	// Set the base address to the correct module.
	mPeInstance->SetBaseAddress(masterMod->BaseAddress);

	// Ordinal import or named import? Differentiate here, the backend will take care of the rest.
	if (wasOrdinal)
	{
		param = (char*)entry.Ordinal;
		cpthw = new CryPlaceIATHookWindow(&newAddress, CrySearchIml::PlaceHookSmall());
	}
	else
	{
		param = entry.FunctionName;
		cpthw = new CryPlaceIATHookWindow(&newAddress, CrySearchIml::PlaceHookSmall());
	}
	
	// Execute the hook dialog and catch return value.
	if (cpthw->Execute() == 10)
	{
#ifdef _WIN64
		if (!mPeInstance->PlaceIATHook(masterMod, param, newAddress, wasOrdinal))
#else
		if (!mPeInstance->PlaceIATHook(masterMod, param, newAddress, wasOrdinal))
#endif
		{
			Prompt("Fatal Error", CtrlImg::error(), "Failed to set the hook!", "OK");
		}
	}
	
	delete cpthw;
	
	// Reload imports to view the hooked import.
	this->RefreshImports();
}

// Executed when the retrieval of data is done.
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

// Forces redraw of the function list; executed when the user selects a different module.
void CryImportsWindow::ModuleRedraw()
{
	this->ModuleChanged();
}

// Executed when the selected module changes.
void CryImportsWindow::ModuleChanged()
{
	MasterIndex = this->mModulesList.GetCursor();
	const int virtualcount = MasterIndex >= 0 && LoadedProcessPEInformation.ImportAddressTable.GetCount() > 0 ? LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList.GetCount() : 0;
	this->mFunctionsList.SetVirtualCount(virtualcount);
	
	// The import table should contain something.
	if (virtualcount)
	{
		// Iterate imported functions for the currently selected module and draw hooked functions in red.
		const Vector<ImportAddressTableEntry>& list = LoadedProcessPEInformation.ImportAddressTable[MasterIndex].FunctionList;
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
		
		this->mFunctionCount.SetLabel(Format("Total %i functions", virtualcount));
	}
	else
	{
		this->mFunctionCount.SetLabel("Total 0 functions");
	}
}

// Refreshes the list of functions inside the selected module's import table.
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

// The imports window initialization function; populates the window.
void CryImportsWindow::Initialize()
{
	// Try to parse the import address table of the target process or one of its modules.
	const bool succeeded = mPeInstance->GetImportAddressTable();
	
	// Did we succeed? In case we did not, the imports were probably parsed, but the target executable may be packed.
	if (!succeeded && SettingsFile::GetInstance()->GetWarnForPackedProcess())
	{
		Prompt("Warning", CtrlImg::exclamation(), "Some imports were not parsed succesfully. The application may be packed!", "OK");
	}
	
	// Set the user interface to display the imports.
	const int modCount = mModuleManager->GetModuleCount();
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

	// Update the user interface with the amount of entries in the import table.
	this->mModulesList.SetVirtualCount(LoadedProcessPEInformation.ImportAddressTable.GetCount());
	
	// If the import table is not empty, update the user interface to point at the first entry.
	if (LoadedProcessPEInformation.ImportAddressTable.GetCount())
	{
		this->mModulesList.SetCursor(0);
	}
		
	// Trigger the event to load the functions inside an imported module.
	this->ModuleChanged();
}

// Just in case, a function that clears everything in this window to avoid problems.
void CryImportsWindow::ClearList()
{
	this->mModulesList.SetVirtualCount(0);
	this->mFunctionsList.SetVirtualCount(0);
	this->mModulesDropList.SetCount(0);
	LoadedProcessPEInformation.ClearImportTable();
}

// Updates the toolbar inside this lower pane window instance.
void CryImportsWindow::UpdateToolbar()
{
	this->mToolStrip.Set(THISBACK(ToolStrip));
}