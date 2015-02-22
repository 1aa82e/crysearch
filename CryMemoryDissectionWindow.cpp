#include "CryMemoryDissectionWindow.h"
#include "CryMemoryDissectionChangePointerWindow.h"
#include "CryMemoryDissectionNewWindow.h"
#include "CryMemoryDissectionSettingsWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

// ---------------------------------------------------------------------------------------------

// Global variable to keep track of how addresses in the dissection should be displayed.
BOOL DissectionAddressViewMode = FALSE;

// Global variable to keep track of whether dissection rows should be displayed in hexadecimal.
BOOL DissectionRowValueHexMode = FALSE;

// Global variable to keep track of which memory dissection entry was selected.
int MemoryDissectionMasterIndex = 0;

// Custom display to draw memory dissection entry addresses including their type.
struct MemoryDissectionEntryDisplay : public Display
{
public:
	void Paint(Draw& w, const Rect& r, const Value& q, Color ink, Color paper, dword style) const
	{
		PaintBackground(w, r, q, ink, paper, style);
		const String& str = q.ToString();
		const int sep = str.FindFirstOf("-");
		String addr = str.Left(sep);
		String type = str.Mid(sep + 2);
		const Font& dFont = StdFont();
		w.DrawText(r.left, r.top, addr, dFont, Black());
		w.DrawText(r.left + (dFont.GetCy() * addr.GetLength()), r.top, type, dFont, Gray());
	}
} MemoryDissectionEntryDrawInstance;

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
	MemoryDissectionEntry* dissection = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	const DissectionRowEntry* entry = dissection->AssociatedDissector[index];
	const SIZE_T addr = dissection->AssociatedDissector.GetBaseAddress();
	
	if (!DissectionAddressViewMode)
	{
#ifdef _WIN64
		return Format("%llX - (%s)", (LONG_PTR)addr + entry->RowOffset, GetCrySearchDataTypeRepresentation(entry->RowType));
#else
		return Format("%lX - (%s)", (LONG_PTR)addr + entry->RowOffset, GetCrySearchDataTypeRepresentation(entry->RowType));
#endif		
	}
	else
	{
		return Format("%lX - (%s)", (LONG_PTR)entry->RowOffset, GetCrySearchDataTypeRepresentation(entry->RowType));	
	}
}

String GetDissectionValue(const int index)
{
	MemoryDissectionEntry* dissection = loadedTable.GetDissection(MemoryDissectionMasterIndex);
	const DissectionRowEntry* entry = dissection->AssociatedDissector[index];
	const SIZE_T addr = dissection->AssociatedDissector.GetBaseAddress() + entry->RowOffset;
	
	// Read data from the address of the row.
	const int readSize = entry->DataLength ? entry->DataLength : sizeof(__int64);
	Byte* buffer = new Byte[readSize];
	SIZE_T bytesRead;
	String representation = "???";
	if (CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)addr, buffer, readSize, &bytesRead))
	{
		// Construct a string representation of the data.
		representation = ValueAsStringInternal(buffer, entry->RowType, entry->DataLength, DissectionRowValueHexMode);
	}
	
	delete[] buffer;
	return representation;
}

// ---------------------------------------------------------------------------------------------

CryMemoryDissectionWindow::CryMemoryDissectionWindow(const AddressTableEntry* const pEntry)
{
	this->Title("Memory Dissection").Zoomable().Sizeable().Icon(CrySearchIml::MemoryDissection()).SetRect(0, 0, 500, 400);
	
	this->AddFrame(this->mMenuBar);
	this->mMenuBar.Set(THISBACK(WindowMenuBar));
	
	*this << this->mDissection.MultiSelect().NoGrid().NoMovingHeader().SizePos();
	
	// Set properties of row-specific size input field.
	this->mRowSizeControl.WhenValueSet = THISBACK(RowEntryChangeDataSize);
	
	this->mDissection.WhenBar = THISBACK(DissectionRightClick);
	this->mDissection.CryAddRowNumColumn("Address", 65).SetConvert(Single<IndexBasedValueConvert<GetDissectionAddress>>()).SetDisplay(MemoryDissectionEntryDrawInstance);
	this->mDissection.CryAddRowNumColumn("Value", 35).SetConvert(Single<IndexBasedValueConvert<GetDissectionValue>>());
	
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
	
	DissectionRowValueHexMode = SettingsFile::GetInstance()->GetDissectionHexadecimalView();
	
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
	pBar.Add("View as hexadecimal", THISBACK(ToggleHexadecimalView)).Check(DissectionRowValueHexMode);
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
	pBar.Add("Float", THISBACK(OffsetMenuFloat));
	pBar.Add("Double", THISBACK(OffsetMenuDouble));
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
	// Get selected dissection to find out which type is currently set.
	const DissectionRowEntry* row = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[this->mDissection.GetCursor()];
	
	// Add menu items with type check.
	pBar.Add("Byte", THISBACK(RowOffsetMenuByte)).Check(row->RowType == CRYDATATYPE_BYTE);
	pBar.Add("2 Bytes", THISBACK(RowOffsetMenuTwoBytes)).Check(row->RowType == CRYDATATYPE_2BYTES);
	pBar.Add("4 Bytes", THISBACK(RowOffsetMenuFourBytes)).Check(row->RowType == CRYDATATYPE_4BYTES);
	pBar.Add("8 Bytes", THISBACK(RowOffsetMenuEightBytes)).Check(row->RowType == CRYDATATYPE_8BYTES);
	pBar.Add("Float", THISBACK(RowOffsetMenuFloat)).Check(row->RowType == CRYDATATYPE_FLOAT);
	pBar.Add("Double", THISBACK(RowOffsetMenuDouble)).Check(row->RowType == CRYDATATYPE_DOUBLE);
	pBar.Add("Array of Bytes", THISBACK(RowOffsetMenuAOB)).Check(row->RowType == CRYDATATYPE_AOB);
	pBar.Add("String", THISBACK(RowOffsetMenuString)).Check(row->RowType == CRYDATATYPE_STRING);
	pBar.Add("WString", THISBACK(RowOffsetMenuWString)).Check(row->RowType == CRYDATATYPE_WSTRING);
	
	// If the selected type is aob, string or wstring, the size should be editable.
	if (row->RowType == CRYDATATYPE_AOB || row->RowType == CRYDATATYPE_STRING || row->RowType == CRYDATATYPE_WSTRING)
	{
		pBar.Separator();
		pBar.Add("Set Length", this->mRowSizeControl.LeftPos(0, 130).TopPos(0));
		pBar.Separator();
		this->mRowSizeControl.SetValueInt(row->DataLength);
	}
}

// ---------------------------------------------------------------------------------------------

// Update function that refreshes the visible rows of memory dissection.
void CryMemoryDissectionWindow::IntervalUpdateDissection()
{
	// Set the array control to refresh, forcing the values to update.
	this->mDissection.Refresh();
	
	// Reinstall time callback function for the next interval.
	this->SetTimeCallback(SettingsFile::GetInstance()->GetDissectionUpdateInterval(), THISBACK(IntervalUpdateDissection), 10);
}

// Refreshes the dissection that is currently selected.
void CryMemoryDissectionWindow::RefreshDissection()
{
	const int count = loadedTable.GetDissectionCount();
	
	// Master index is not always safe. We should check the dissection count, just in case.
	if (count)
	{
		// Attempt to read and dissect the selected memory block.
		MemoryDissectionEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex);
		if (!entry->AssociatedDissector.GetDissectionRowCount())
		{
			// The default row offset should be 4 but we should also take into account that the user may want to enable type guessing.
			if (entry->AssociatedDissector.Dissect(sizeof(DWORD), SettingsFile::GetInstance()->GetEnableDissectionTypeGuessing()))
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
			// The memory dissection already contains rows. Just load the rows into the window display.
			this->mDissection.SetVirtualCount(entry->AssociatedDissector.GetDissectionRowCount());
		}
	}
	else
	{
		this->mDissection.Clear();
	}
}

// ---------------------------------------------------------------------------------------------

// Toggles the address view mode for the first column.
void CryMemoryDissectionWindow::AddressViewModeClicked()
{
	DissectionAddressViewMode = !DissectionAddressViewMode;
	if (loadedTable.GetDissectionCount())
	{
		this->mDissection.SetVirtualCount(loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.GetDissectionRowCount());
	}
}

// Sets the memory dissection size to one byte.
void CryMemoryDissectionWindow::OffsetMenuByte()
{
	loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.SetGlobalDissectionType(CRYDATATYPE_BYTE);
}

// Sets the memory dissection size to two bytes.
void CryMemoryDissectionWindow::OffsetMenuTwoBytes()
{
	loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.SetGlobalDissectionType(CRYDATATYPE_2BYTES);
}

// Sets the memory dissection size to four bytes.
void CryMemoryDissectionWindow::OffsetMenuFourBytes()
{
	loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.SetGlobalDissectionType(CRYDATATYPE_4BYTES);
}

// Sets the memory dissection size to eight bytes.
void CryMemoryDissectionWindow::OffsetMenuEightBytes()
{
	loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.SetGlobalDissectionType(CRYDATATYPE_8BYTES);
}

// Sets the memory dissection type to float.
void CryMemoryDissectionWindow::OffsetMenuFloat()
{
	loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.SetGlobalDissectionType(CRYDATATYPE_FLOAT);
}

// Sets the memory dissection type to double.
void CryMemoryDissectionWindow::OffsetMenuDouble()
{
	loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.SetGlobalDissectionType(CRYDATATYPE_DOUBLE);
}

// ---------------------------------------------------------------------------------------------

// Changes the size of a string, wstring or aob row data type. Only called in case of this data type.
void CryMemoryDissectionWindow::RowEntryChangeDataSize(const int value)
{
	const int row = this->mDissection.GetCursor();
	int* const lenPtr = &loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row]->DataLength;
	const int oldLen = *lenPtr;
	*lenPtr = value;
	this->AlterSuccessingRows(row, value - oldLen);
}

// When a row is altered, the successing rows must be altered as well.
void CryMemoryDissectionWindow::AlterSuccessingRows(const int row, const int diff)
{
	const int count = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.GetDissectionRowCount();
	for (int i = max(row, 1); i < count; ++i)
	{
		// Increment every dissection entry by the specified difference.
		loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[i]->RowOffset += diff;
	}
}

// Sets the memory dissection size of the selected row to one byte.
void CryMemoryDissectionWindow::RowOffsetMenuByte()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_BYTE;
	entry->DataLength = 0;
	this->AlterSuccessingRows(row, GetDataSizeFromValueType(CRYDATATYPE_BYTE) - oldSize);
}

// Sets the memory dissection size of the selected row to two bytes.
void CryMemoryDissectionWindow::RowOffsetMenuTwoBytes()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_2BYTES;
	entry->DataLength = 0;
	this->AlterSuccessingRows(row, GetDataSizeFromValueType(CRYDATATYPE_2BYTES) - oldSize);
}

// Sets the memory dissection size of the selected row to four bytes.
void CryMemoryDissectionWindow::RowOffsetMenuFourBytes()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_4BYTES;
	entry->DataLength = 0;
	this->AlterSuccessingRows(row, GetDataSizeFromValueType(CRYDATATYPE_4BYTES) - oldSize);
}

// Sets the memory dissection size of the selected row to eight bytes.
void CryMemoryDissectionWindow::RowOffsetMenuEightBytes()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_8BYTES;
	entry->DataLength = 0;
	this->AlterSuccessingRows(row, GetDataSizeFromValueType(CRYDATATYPE_8BYTES) - oldSize);
}

// Sets the memory dissection type of the selected row to float.
void CryMemoryDissectionWindow::RowOffsetMenuFloat()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_FLOAT;
	entry->DataLength = 0;
	this->AlterSuccessingRows(row, GetDataSizeFromValueType(CRYDATATYPE_FLOAT) - oldSize);
}

// Sets the memory dissection type of the selected row to double.
void CryMemoryDissectionWindow::RowOffsetMenuDouble()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_DOUBLE;
	entry->DataLength = 0;
	this->AlterSuccessingRows(row, GetDataSizeFromValueType(CRYDATATYPE_DOUBLE) - oldSize);
}

// Sets the memory dissection type of the selected row to AOB.
void CryMemoryDissectionWindow::RowOffsetMenuAOB()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = entry->DataLength ? entry->DataLength : GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_AOB;
	entry->DataLength = GetDataSizeFromValueType(CRYDATATYPE_AOB);
	this->AlterSuccessingRows(row, entry->DataLength - oldSize);
}

// Sets the memory dissection type of the selected row to string.
void CryMemoryDissectionWindow::RowOffsetMenuString()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = entry->DataLength ? entry->DataLength : GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_STRING;
	entry->DataLength = GetDataSizeFromValueType(CRYDATATYPE_STRING);
	this->AlterSuccessingRows(row, entry->DataLength - oldSize);
}

// Sets the memory dissection type of the selected row to wstring.
void CryMemoryDissectionWindow::RowOffsetMenuWString()
{
	const int row = this->mDissection.GetCursor();
	DissectionRowEntry* entry = loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector[row];
	const int oldSize = entry->DataLength ? entry->DataLength : GetDataSizeFromValueType(entry->RowType);
	entry->RowType = CRYDATATYPE_WSTRING;
	entry->DataLength = GetDataSizeFromValueType(CRYDATATYPE_STRING);
	this->AlterSuccessingRows(row, entry->DataLength - oldSize);
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
	DissectionRowValueHexMode = !DissectionRowValueHexMode;
	if (loadedTable.GetDissectionCount())
	{
		this->mDissection.SetVirtualCount(loadedTable.GetDissection(MemoryDissectionMasterIndex)->AssociatedDissector.GetDissectionRowCount());
	}
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
	if (cmdsw->Execute() == 10)
	{
		// Reload the hexadecimal toggle value.
		DissectionRowValueHexMode = SettingsFile::GetInstance()->GetDissectionHexadecimalView();		
	}
	
	delete cmdsw;

	// Most likely it is useful to refresh the dissection, but only if there actually are dissections.
	if (loadedTable.GetDissectionCount() > 0)
	{
		this->RefreshDissection();
	}
}