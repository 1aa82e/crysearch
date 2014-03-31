#include "CryAddHotkeyWindow.h"

// The lookup table, allocated once at runtime. This table is used to convert hotkey fields from and to user interface views.
HotkeyLookupTableEntry HotkeyLookupTable[] = 
{
	{ VK_F1, "F1" },
	{ VK_F2, "F2" },
	{ VK_F3, "F3" },
	{ VK_F4, "F4" },
	{ VK_F5, "F5" },
	{ VK_F6, "F6" },
	{ VK_F7, "F7" },
	{ VK_F8, "F8" },
	{ VK_F9, "F9" },
	{ VK_F10, "F10" },
	{ VK_F11, "F11" },
	{ VK_F12, "F12" },
	{ VK_NUMPAD0, "Numpad 0" },
	{ VK_NUMPAD1, "Numpad 1" },
	{ VK_NUMPAD2, "Numpad 2" },
	{ VK_NUMPAD3, "Numpad 3" },
	{ VK_NUMPAD4, "Numpad 4" },
	{ VK_NUMPAD5, "Numpad 5" },
	{ VK_NUMPAD6, "Numpad 6" },
	{ VK_NUMPAD7, "Numpad 7" },
	{ VK_NUMPAD8, "Numpad 8" },
	{ VK_NUMPAD9, "Numpad 9" }
};

String& HotkeyToString(const unsigned int hotkey)
{
	for (unsigned int i = 0; i < sizeof(HotkeyLookupTable) / sizeof(HotkeyLookupTable[0]); i++)
	{
		if (HotkeyLookupTable[i].KeyCode == hotkey)
		{
			return HotkeyLookupTable[i].StringRepresentation;
		}
	}
	
	// Compiler does not need to generate a return statement here, because it will never be reached. Make it assume so to minimize code generation.
	__assume(0);
}

unsigned int KeycodeFromString(const String& stringRepresentation)
{
	for (unsigned int i = 0; i < sizeof(HotkeyLookupTable) / sizeof(HotkeyLookupTable[0]); i++)
	{
		if (HotkeyLookupTable[i].StringRepresentation == stringRepresentation)
		{
			return HotkeyLookupTable[i].KeyCode;
		}
	}
	
	// The compiler does need to generate a return statement here because it will never be reached. Make it assume so to reduce code generation.
	__assume(0);
}

CryAddHotkeyWindow::CryAddHotkeyWindow(CrySearchHotKey* entry)
{
	this->mAlterEntry = entry;
	
	this->Title("Add Hotkey").SetRect(0, 0, 325, 100);
	
	this->mOK <<= THISBACK(DialogOkay);
	this->mCancel <<= THISBACK(DialogCancel);
	
	*this
		<< this->mHotkeyActionDescription.SetLabel("Action:").LeftPos(5, 75).TopPos(5, 20)
		<< this->mHotkeyAction.Add("Refresh search results, changed value").Add("Refresh search results, unchanged value")
			.Add("Refresh search results, increased value").Add("Refresh search results, decreased value").HSizePos(80, 5).TopPos(5, 20)
		<< this->mHotkeyDescription.SetLabel("Hotkey").LeftPos(5, 75).TopPos(30, 20)
		<< this->mHotkey.HSizePos(80, 5).TopPos(30, 20)
		<< this->mOK.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 20)
		<< this->mCancel.SetLabel("Cancel").RightPos(70, 60).BottomPos(5, 20)
	;
	
	for (unsigned int i = 0; i < sizeof(HotkeyLookupTable) / sizeof(HotkeyLookupTable[0]); i++)
	{
		this->mHotkey.Add(HotkeyLookupTable[i].StringRepresentation);
	}
	
	if (entry)
	{
		this->mHotkeyAction.SetIndex(this->mHotkeyAction.Find(entry->Description));
		this->mHotkey.SetIndex(this->mHotkey.Find(HotkeyToString(entry->Key)));
	}
	else
	{
		this->mHotkeyAction.SetIndex(0);
		this->mHotkey.SetIndex(0);		
	}
}

CryAddHotkeyWindow::~CryAddHotkeyWindow()
{
	
}

bool CryAddHotkeyWindow::Key(dword key, int count)
{
	if (key == K_ESCAPE)
	{
		this->Close();
		return true;
	}
	
	return false;
}

void CryAddHotkeyWindow::DialogOkay()
{
	const String& selectedKey = this->mHotkeyAction.GetValue();
	unsigned int key = KeycodeFromString(this->mHotkey.GetValue());
	
	for (unsigned int i = 0; i < GlobalSettingsInstance.GetHotkeyCount(); i++)
	{
		const CrySearchHotKey& curKey = GlobalSettingsInstance.GetHotkey(i);
		if (curKey.Description == selectedKey || curKey.Key == key)
		{
			Prompt("Input Error", CtrlImg::error(), "The selected hotkey is already occupied. Please select a different key.", "OK");
			return;
		}
	}
	
	GlobalSettingsInstance.AddHotkey(selectedKey, key);
	
	this->Close();
}

void CryAddHotkeyWindow::DialogCancel()
{
	this->Close();
}