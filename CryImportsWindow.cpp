#include "CryImportsWindow.h"
#include "ProcessUtil.h"
#include "CryPlaceIATHookWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// Global pointer necessary here to explicitly grant access to row indexes from Display struct.
CrySearchArrayCtrl* FunctionEntriesArrayCtrl;

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

CryImportsWindow::CryImportsWindow()
{
	FunctionEntriesArrayCtrl = &this->mFunctionsList;
	
	this->mModulesList.AddRowNumColumn("Module").SetConvert(Single<IndexBasedValueConvert<GetModule>>());
	this->mFunctionsList.AddRowNumColumn("Function", 60).SetConvert(Single<IndexBasedValueConvert<GetFunction>>());
	this->mFunctionsList.AddRowNumColumn("Hint", 15).SetConvert(Single<IndexBasedValueConvert<GetHint>>());
	this->mFunctionsList.AddRowNumColumn("Virtual Address", 25).SetConvert(Single<IndexBasedValueConvert<GetVirtualAddress>>());
	
	this->mFunctionsList.WhenBar = THISBACK(FunctionListRightClick);
	
	this->mModulesList.WhenSel = THISBACK(ModuleChanged);

	*this << this->mControlSplitter.Horz(this->mModulesList.SizePos(), this->mFunctionsList.SizePos());

	this->mControlSplitter.SetMinPixels(0, 150);
	this->mControlSplitter.SetMinPixels(1, 300);
	this->mControlSplitter.SetPos(3500);
}

CryImportsWindow::~CryImportsWindow()
{
	
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
	
	pBar.Add("Refresh", CrySearchIml::RefreshButtonSmall(), THISBACK(RefreshImports));
}

void CryImportsWindow::RestoreIATFunction()
{
	const ImportTableDescriptor& key = LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex);
	const ImportAddressTableEntry& entry = LoadedProcessPEInformation.ImportAddressTable.Get(key)[this->mFunctionsList.GetCursor()];
	
	if (key.LogicalBaseAddress)
	{
		mPeInstance->RestoreExportTableAddressImport(key.LogicalBaseAddress, entry.Ordinal ? (char*)entry.Ordinal : entry.FunctionName, entry.Ordinal);
	}
	else
	{
		mPeInstance->RestoreExportTableAddressImport(FindModuleInVector(LoadedProcessPEInformation.ImportAddressTable.GetKey(this->mModulesList.GetCursor()).ModuleName)->BaseAddress, entry.Ordinal ? (char*)entry.Ordinal : entry.FunctionName, entry.Ordinal);
	}
	
	this->RefreshImports();
}

void CryImportsWindow::PlaceHookOnIATFunction()
{
	const ImportAddressTableEntry& entry = LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex)).At(this->mFunctionsList.GetCursor());
	const char* param = NULL;
	CryPlaceIATHookWindow* cpthw = NULL;
	
	// Check for the EAT address associated to the function. If the EAT address is not found, the address cannot be restored later.
	if (entry.Flag == IAT_FLAG_NOT_FOUND && !Prompt("I need your confirmation", CtrlImg::exclamation(),
		"The address of this function could not be found in the export table of the module. Therefore the address cannot be restored. Are you sure you want to place a hook on this function?"
		, "Yes", "No"))
	{
		return;
	}
	
	// Ordinal import or named import? Differentiate here, the backend will take care of the rest.
	if (entry.Ordinal == 0)
	{
		param = entry.FunctionName;
		cpthw = new CryPlaceIATHookWindow(param, false);
	}
	else
	{
		param = (char*)entry.Ordinal;
		cpthw = new CryPlaceIATHookWindow(param, true);
	}
	
	cpthw->Execute();
	delete cpthw;
	
	// Reload imports to view the hooked import.
	this->RefreshImports();
}

void CryImportsWindow::ModuleChanged()
{
	MasterIndex = this->mModulesList.GetCursor();
	this->mFunctionsList.SetVirtualCount(LoadedProcessPEInformation.ImportAddressTable.Get(LoadedProcessPEInformation.ImportAddressTable.GetKey(MasterIndex)).GetCount());
	
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

void CryImportsWindow::RefreshImports()
{
	LoadedProcessPEInformation.ClearImportTable();
	this->Initialize();
}

void CryImportsWindow::Initialize()
{
	mPeInstance->GetImportAddressTable();
	
	// If the IAT could not be loaded, and is empty, do not trigger the event. This will crash CrySearch.
	if (LoadedProcessPEInformation.ImportAddressTable.GetCount())
	{
		this->mModulesList.SetVirtualCount(LoadedProcessPEInformation.ImportAddressTable.GetCount());
		this->mModulesList.SetCursor(0);
		
		this->ModuleChanged();
	}
}