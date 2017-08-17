#ifndef _CrySearch_CryMemoryDissectionWindow_h_
#define _CrySearch_CryMemoryDissectionWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"
#include "AddressTable.h"
#include "DissectionRowSizeCtrl.h"

// Represents the memory dissection window inside the CrySearch main window menu.
class CryMemoryDissectionWindow : public TopWindow
{
private:
	const AddressTableEntry* mExecuteNewEntryOnce;
	MenuBar mMenuBar;
	VirtualDropList mAvailableDissections;
	CrySearchArrayCtrl mDissection;
	DissectionRowSizeCtrl mRowSizeControl;
	
	void WindowMenuBar(Bar& pBar);
	void FileMenuBar(Bar& pBar);
	void DissectionMenuBar(Bar& pBar);
	void ViewMenuBar(Bar& pBar);
	void DissectionRightClick(Bar& pBar);
	void SetOffsetsMenuOpened(Bar& pBar);
	void ChangeRowOffsetMenu(Bar& pBar);
	void ViewAddressesAsMenu(Bar& pBar);
	
	void NewDissectionFromSelectedPointer();
	void DissectionEntryDoubleClicked();
	void AddRowToAddressList();
	void ToggleDissectionFreezeThaw();
	void ChangeRowValue();
	void NewDissectionFromAddressTableEntry();
	void CloseWindow();
	void SettingsMenuClicked();
	void EditDissectionClicked();
	void RemoveDissectionFromList();
	void NewStructureClicked();
	void MemoryDissectionEntryChanged();
	void MemoryDissectionEntryDropped();
	void ToggleHexadecimalView();
	void RefreshDissection(const CCryDataType globalType);
	void IntervalUpdateDissection();
	void OffsetMenuByte();
	void OffsetMenuTwoBytes();
	void OffsetMenuFourBytes();
	void OffsetMenuEightBytes();
	void OffsetMenuFloat();
	void OffsetMenuDouble();
	void RowOffsetMenuByte();
	void RowOffsetMenuTwoBytes();
	void RowOffsetMenuFourBytes();
	void RowOffsetMenuEightBytes();
	void RowOffsetMenuFloat();
	void RowOffsetMenuDouble();
	void RowOffsetMenuAOB();
	void RowOffsetMenuString();
	void RowOffsetMenuWString();
	void AddressViewModeClicked();
	void RowEntryChangeDataSize(const int value);
	void AlterSuccessingRows(const int row, const int diff);
	
	typedef CryMemoryDissectionWindow CLASSNAME;
public:
	CryMemoryDissectionWindow(const AddressTableEntry* const pEntry);
	~CryMemoryDissectionWindow();
};

#endif