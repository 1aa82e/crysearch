#ifndef _CrySearch_CryMemoryDissectionWindow_h_
#define _CrySearch_CryMemoryDissectionWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"
#include "AddressTable.h"

// Represents the memory dissection window inside the CrySearch main window menu.
class CryMemoryDissectionWindow : public TopWindow
{
private:
	const AddressTableEntry* mExecuteNewEntryOnce;
	MenuBar mMenuBar;
	VirtualDropList mAvailableDissections;
	CrySearchArrayCtrl mDissection;
	
	void WindowMenuBar(Bar& pBar);
	void FileMenuBar(Bar& pBar);
	void DissectionMenuBar(Bar& pBar);
	void ViewMenuBar(Bar& pBar);
	void DissectionRightClick(Bar& pBar);
	void SetOffsetsMenuOpened(Bar& pBar);
	void ChangeRowOffsetMenu(Bar& pBar);
	void ViewAddressesAsMenu(Bar& pBar);
	
	void NewDissectionFromAddressTableEntry();
	void CloseWindow();
	void SettingsMenuClicked();
	void ChangePointerClicked();
	void RemoveDissectionFromList();
	void NewStructureClicked();
	void MemoryDissectionEntryChanged();
	void MemoryDissectionEntryDropped();
	void ToggleHexadecimalView();
	void RefreshDissection();
	void IntervalUpdateDissection();
	void OffsetMenuByte();
	void OffsetMenuTwoBytes();
	void OffsetMenuFourBytes();
	void OffsetMenuEightBytes();
	void RowOffsetMenuByte();
	void RowOffsetMenuTwoBytes();
	void RowOffsetMenuFourBytes();
	void RowOffsetMenuEightBytes();
	void AddressViewModeClicked();
	
	typedef CryMemoryDissectionWindow CLASSNAME;
public:
	CryMemoryDissectionWindow(const AddressTableEntry* const pEntry);
	~CryMemoryDissectionWindow();
};

#endif