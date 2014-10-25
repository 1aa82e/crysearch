#include "CryMemoryDissectionWindow.h"
#include "CryMemoryDissectionChangePointerWindow.h"
#include "CryMemoryDissectionNewWindow.h"
#include "CryMemoryDissectionSettingsWindow.h"
#include "ImlProvider.h"
#include "GlobalDef.h"

// ---------------------------------------------------------------------------------------------

// Global variable to keep track of how addresses in the dissection should be displayed.
BOOL DissectionAddressViewMode = FALSE;

// Global variable to keep track of which memory dissection entry was selected.
int MemoryDissectionMasterIndex = 0;

// ---------------------------------------------------------------------------------------------

String GetDissectionForDropList(const int index)
{
	// The VirtualDropList control seems to behave strangely when the form is closed and no items are left.
	if (loadedTable.GetDissectionCount() > 0)
	{
		const MemoryDissectionEntry* dissection = loadedTable.GetDissection(index);
#ifdef _WIN64
		return Format("%s - (%llX)", dissection->FriendlyName, (LONG_PTR)dissection->AssociatedDissector.GetBaseAddress());
#else
		return Format("%s - (%lX)", dissection->FriendlyName, (LONG_PTR)dissection->AssociatedDissector.GetBaseAddress());
#endif		
	}
	else
	{
		return "";
	}
}

String GetDissectionAddress(const int index)
{
	const MemoryDissectionEntry* dissection = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	const SIZE_T addr = dissection->AssociatedDissector.GetBaseAddress();
	
	if (!DissectionAddressViewMode)
	{
#ifdef _WIN64
	return Format("%llX", (LONG_PTR)addr + dissection->AssociatedDissector[index]->RowOffset);
#else
	return Format("%lX", (LONG_PTR)addr + dissection->AssociatedDissector[index]->RowOffset);
#endif		
	}
	else
	{
	return Format("%lX", (LONG_PTR)dissection->AssociatedDissector[index]->RowOffset);	
	}
}

String GetDissectionValue(const int index)
{
	// Need to check this! (Different row sizes will bring trouble)
	if (SettingsFile::GetInstance()->GetDissectionHexadecimalView())
	{
		return Format("%lX", (LONG_PTR)loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[index]->RowValue);
	}
	else
	{
		return Format("%li", (LONG_PTR)loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[index]->RowValue);
	}
}

// ---------------------------------------------------------------------------------------------

CryMemoryDissectionWindow::CryMemoryDissectionWindow(const AddressTableEntry* const pEntry)
{
	this->Title("Memory Dissection").Zoomable().Sizeable().Icon(CrySearchIml::MemoryDissection()).SetRect(0, 0, 500, 400);
	
	this->AddFrame(this->mMenuBar);
	this->mMenuBar.Set(THISBACK(WindowMenuBar));
	
	*this << this->mDissection.MultiSelect().NoGrid().NoMovingHeader().SizePos();
	
	this->mDissection.WhenBar = THISBACK(DissectionRightClick);
	this->mDissection.AddRowNumColumn("Address").SetConvert(Single<IndexBasedValueConvert<GetDissectionAddress>>());
	this->mDissection.AddRowNumColumn("Value").SetConvert(Single<IndexBasedValueConvert<GetDissectionValue>>());
	
	// Add existing dissections to drop list.
	this->mAvailableDissections.SetConvert(Single<IndexBasedValueConvert<GetDissectionForDropList>>());
	this->mAvailableDissections.WhenAction = THISBACK(MemoryDissectionEntryChanged);
	this->mAvailableDissections.WhenDrop = THISBACK(MemoryDissectionEntryDropped);
	
	// Add available dissections to drop list.
	const int count = loadedTable.GetDissectionCount();
	this->mAvailableDissections.SetCount(count);
	if (count > 0)
	{
		this->mAvailableDissections.SetIndex(0);
		this->RefreshDissection();
	}
	
	// This variable is set by the caller that creates the dissection window. It indicates whether
	// a new dissection entry should be created from an address table entry.
	this->mExecuteNewEntryOnce = pEntry;
	if (this->mExecuteNewEntryOnce)
	{
		this->NewDissectionFromAddressTableEntry();
	}
	
	// Install time interval callback to dynamically refresh dissection.
	this->SetTimeCallback(SettingsFile::GetInstance()->GetDissectionUpdateInterval(), THISBACK(IntervalUpdateDissection), 10);
}

CryMemoryDissectionWindow::~CryMemoryDissectionWindow()
{
	// Kill running update callback before destroying the window.
	KillTimeCallback(10);
}

void CryMemoryDissectionWindow::WindowMenuBar(Bar& pBar)
{
	pBar.Add("File", THISBACK(FileMenuBar));
	pBar.Add("Dissection", THISBACK(DissectionMenuBar));
	pBar.Add("View", THISBACK(ViewMenuBar));
	
	// The available dissections droplist should be located on the right of the menu bar.
	pBar.MenuGapRight();
	pBar.Add(this->mAvailableDissections, 200);
}

void CryMemoryDissectionWindow::FileMenuBar(Bar& pBar)
{
	pBar.Add("New", CrySearchIml::AddToAddressList(), THISBACK(NewStructureClicked));
	pBar.Add("Close", CrySearchIml::ExitApplication(), THISBACK(CloseWindow));
}

void CryMemoryDissectionWindow::DissectionMenuBar(Bar& pBar)
{
	// Check if the menu items should be enabled or disabled.
	const bool allowed = !!loadedTable.GetDissectionCount() && this->mAvailableDissections.GetIndex() >= 0;
	
	pBar.Add(allowed, "Change Pointer", CrySearchIml::ChangeRecordIcon(), THISBACK(ChangePointerClicked));
	pBar.Add(allowed, "Set Types", THISBACK(SetOffsetsMenuOpened));
	pBar.Separator();
	pBar.Add(allowed, "Remove", CrySearchIml::DeleteButton(), THISBACK(RemoveDissectionFromList));
}

void CryMemoryDissectionWindow::ViewMenuBar(Bar& pBar)
{
	pBar.Add("View as hexadecimal", THISBACK(ToggleHexadecimalView)).Check(SettingsFile::GetInstance()->GetDissectionHexadecimalView());
	pBar.Add("View addresses as", THISBACK(ViewAddressesAsMenu));
	pBar.Separator();
	pBar.Add("Settings", CrySearchIml::SettingsButton(), THISBACK(SettingsMenuClicked));
}

void CryMemoryDissectionWindow::ViewAddressesAsMenu(Bar& pBar)
{
	pBar.Add("Address", THISBACK(AddressViewModeClicked)).Check(!DissectionAddressViewMode);
	pBar.Add("Offset", THISBACK(AddressViewModeClicked)).Check(DissectionAddressViewMode);
}

void CryMemoryDissectionWindow::SetOffsetsMenuOpened(Bar& pBar)
{
	pBar.Add("Byte", THISBACK(OffsetMenuByte));
	pBar.Add("2 Bytes", THISBACK(OffsetMenuTwoBytes));
	pBar.Add("4 Bytes", THISBACK(OffsetMenuFourBytes));
	pBar.Add("8 Bytes", THISBACK(OffsetMenuEightBytes));
}

void CryMemoryDissectionWindow::DissectionRightClick(Bar& pBar)
{
	const int cursor = this->mDissection.GetCursor();
	if (cursor >= 0 && loadedTable.GetDissection(MemoryDissectionMasterIndex))
	{
		pBar.Add("Change Type", THISBACK(ChangeRowOffsetMenu));
	}
	// generate struct definition for multiple rows?
}

void CryMemoryDissectionWindow::ChangeRowOffsetMenu(Bar& pBar)
{
	pBar.Add("Byte", THISBACK(RowOffsetMenuByte));
	pBar.Add("2 Bytes", THISBACK(RowOffsetMenuTwoBytes));
	pBar.Add("4 Bytes", THISBACK(RowOffsetMenuFourBytes));
	pBar.Add("8 Bytes", THISBACK(RowOffsetMenuEightBytes));
}

// ---------------------------------------------------------------------------------------------

// Update function that refreshes the visible rows of memory dissection.
void CryMemoryDissectionWindow::IntervalUpdateDissection()
{
	// Only run interval based updater if there are dissections available.
	if (loadedTable.GetDissectionCount() > 0)
	{
		// Retrieve range of memory that is visible to the user. We are not going to update the whole memory block every interval.
		Tuple2<int, int> visibleMemory = this->mDissection.GetVisibleRange();
		MemoryDissector* const md = &loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector;
		if (visibleMemory.a >= 0 && visibleMemory.b < md->GetDissectionRowCount())
		{
			md->DissectPartial(visibleMemory);
		}
		
		// Update user interface with dissection results.
		this->mDissection.SetVirtualCount(md->GetDissectionRowCount());		
	}
	
	// Reinstall time callback function for the next interval.
	this->SetTimeCallback(SettingsFile::GetInstance()->GetDissectionUpdateInterval(), THISBACK(IntervalUpdateDissection), 10);
}

// Refreshes the dissection that is currently selected.
void CryMemoryDissectionWindow::RefreshDissection()
{
	const int count = loadedTable.GetDissectionCount() > 0;
	
	// Master index is not always safe. We should check the dissection count, just in case.
	if (count)
	{
		// Attempt to read and dissect the selected memory block.
		MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
		if (entry->AssociatedDissector.Dissect(sizeof(DWORD)))
		{
			// Update user interface with dissection results.
			this->mDissection.SetVirtualCount(entry->AssociatedDissector.GetDissectionRowCount());
		}
		else
		{
			// The memory dissection failed. Display error message and clear out user interface.
			this->mDissection.Clear();
			Prompt("Fatal Error", CtrlImg::error(), "Failed to read specified memory block!", "OK");
		}
	}
	else
	{
		this->mDissection.Clear();
	}
	
	// To save memory when having more than one dissection available, erase resources of invisible dissections.
	for (int i = 0; i < count; ++i)
	{
		if (i != MemoryDissectionMasterIndex)
		{
			loadedTable.GetDissection(i)->AssociatedDissector.Clear();
		}
	}
}

// ---------------------------------------------------------------------------------------------

// Toggles the address view mode for the first column.
void CryMemoryDissectionWindow::AddressViewModeClicked()
{
	DissectionAddressViewMode = !DissectionAddressViewMode;
	this->mDissection.SetVirtualCount(loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.GetDissectionRowCount());
}

// Sets the memory dissection size to one byte.
void CryMemoryDissectionWindow::OffsetMenuByte()
{
	MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	entry->AssociatedDissector.Dissect(sizeof(Byte));
	this->mDissection.SetVirtualCount(entry->AssociatedDissector.GetDissectionRowCount());
}

// Sets the memory dissection size to two bytes.
void CryMemoryDissectionWindow::OffsetMenuTwoBytes()
{
	MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	entry->AssociatedDissector.Dissect(sizeof(short));
	this->mDissection.SetVirtualCount(entry->AssociatedDissector.GetDissectionRowCount());
}

// Sets the memory dissection size to four bytes.
void CryMemoryDissectionWindow::OffsetMenuFourBytes()
{
	MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	entry->AssociatedDissector.Dissect(sizeof(int));
	this->mDissection.SetVirtualCount(entry->AssociatedDissector.GetDissectionRowCount());
}

// Sets the memory dissection size to eight bytes.
void CryMemoryDissectionWindow::OffsetMenuEightBytes()
{
	MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	entry->AssociatedDissector.Dissect(sizeof(__int64));
	this->mDissection.SetVirtualCount(entry->AssociatedDissector.GetDissectionRowCount());
}

// ---------------------------------------------------------------------------------------------

// Sets the memory dissection size of the selected row to one byte.
void CryMemoryDissectionWindow::RowOffsetMenuByte()
{
	
}

// Sets the memory dissection size of the selected row to two bytes.
void CryMemoryDissectionWindow::RowOffsetMenuTwoBytes()
{
	
}

// Sets the memory dissection size of the selected row to four bytes.
void CryMemoryDissectionWindow::RowOffsetMenuFourBytes()
{
	
}

// Sets the memory dissection size of the selected row to eight bytes.
void CryMemoryDissectionWindow::RowOffsetMenuEightBytes()
{
	
}

// ---------------------------------------------------------------------------------------------

// Opens the new dissection dialog with address table entry information filled in.
void CryMemoryDissectionWindow::NewDissectionFromAddressTableEntry()
{
	// Use already implemented pointers to pass values!
	String name = this->mExecuteNewEntryOnce->Description;
	SIZE_T addr = this->mExecuteNewEntryOnce->Address;
	DWORD size = 1024;

	CryMemoryDissectionNewWindow* cmmnw = new CryMemoryDissectionNewWindow(&name, &addr, &size);
	
	// Check if dialog result was OK.
	if (cmmnw->Execute() == 10)
	{
		loadedTable.AddDissection(name, addr, size);
	}
	
	delete cmmnw;
	
	// Refresh available memory dissection entries.
	const int count = loadedTable.GetDissectionCount();
	this->mAvailableDissections.SetCount(count);
	if (count > 0)
	{
		this->mAvailableDissections.SetIndex(count - 1);
		MemoryDissectionMasterIndex = this->mAvailableDissections.GetIndex();
		this->RefreshDissection();
	}
	
	// Reset the variable so this function can not be called again. Just in case.
	this->mExecuteNewEntryOnce = NULL;
}

void CryMemoryDissectionWindow::ToggleHexadecimalView()
{
	// Swap the value of the hexadecimal view option and refresh the user interface.
	SettingsFile::GetInstance()->SetDissectionHexadecimalView(!SettingsFile::GetInstance()->GetDissectionHexadecimalView());
	this->mDissection.SetVirtualCount(loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.GetDissectionRowCount());
}

void CryMemoryDissectionWindow::MemoryDissectionEntryChanged()
{
	MemoryDissectionMasterIndex = this->mAvailableDissections.GetIndex();
	this->RefreshDissection();
}

void CryMemoryDissectionWindow::MemoryDissectionEntryDropped()
{
	this->mAvailableDissections.SetCount(loadedTable.GetDissectionCount());
}

void CryMemoryDissectionWindow::ChangePointerClicked()
{
	MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	SIZE_T ptr = entry->AssociatedDissector.GetBaseAddress();
	CryMemoryDissectionChangePointerWindow* cmdcpw = new CryMemoryDissectionChangePointerWindow(&ptr);

	// Check if dialog result was OK.
	if (cmdcpw->Execute() == 10)
	{
		entry->AssociatedDissector.SetBaseAddress(ptr);
		this->mAvailableDissections.SetCount(loadedTable.GetDissectionCount());
		this->RefreshDissection();
	}
	
	delete cmdcpw;
}

void CryMemoryDissectionWindow::RemoveDissectionFromList()
{
	// Remove the dissection from the address table and refresh the user interface.
	loadedTable.RemoveDissection(MemoryDissectionMasterIndex);
	const int count = loadedTable.GetDissectionCount();
	
	// If the last entry of multiple is removed, the master index will create inconsistency.
	if (count > 0 && MemoryDissectionMasterIndex == count)
	{
		--MemoryDissectionMasterIndex;
	}
	
	if (count > 0)
	{
		this->mAvailableDissections.SetCount(count);
		this->mAvailableDissections.SetIndex(MemoryDissectionMasterIndex);
		this->RefreshDissection();
	}
	else
	{
		this->mAvailableDissections.SetCount(0);
		this->mDissection.Clear();
	}
}

void CryMemoryDissectionWindow::NewStructureClicked()
{
	String name;
	SIZE_T addr = 0;
	DWORD size = 0;
	CryMemoryDissectionNewWindow* cmmnw = new CryMemoryDissectionNewWindow(&name, &addr, &size);
	
	// Check if dialog result was OK.
	if (cmmnw->Execute() == 10)
	{
		loadedTable.AddDissection(name, addr, size);
	}
	
	delete cmmnw;
	
	// Refresh available memory dissection entries.
	const int count = loadedTable.GetDissectionCount();
	this->mAvailableDissections.SetCount(count);
	if (count > 0)
	{
		this->mAvailableDissections.SetIndex(count - 1);
		MemoryDissectionMasterIndex = this->mAvailableDissections.GetIndex();
		this->RefreshDissection();
	}
}

void CryMemoryDissectionWindow::CloseWindow()
{
	this->Close();
}

void CryMemoryDissectionWindow::SettingsMenuClicked()
{
	// Execute the settings window.
	CryMemoryDissectionSettingsWindow* cmdsw = new CryMemoryDissectionSettingsWindow();
	cmdsw->Execute();
	delete cmdsw;
	
	// Most likely it is useful to refresh the dissection, but only if there actually are dissections.
	if (loadedTable.GetDissectionCount() > 0)
	{
		this->RefreshDissection();
	}
}