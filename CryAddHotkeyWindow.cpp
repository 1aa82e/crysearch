#include "CryAddHotkeyWindow.h"

// The lookup table, allocated once at runtime. This table is used to convert hotkey fields from and to user interface views.
const HotkeyLookupTableEntry HotkeyLookupTable[] =
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

// Retrieves the string representation of a specified hotkey.
const char* HotkeyToString(const unsigned int hotkey)
{
	for (unsigned int i = 0; i < sizeof(HotkeyLookupTable) / sizeof(HotkeyLookupTable[0]); i++)
	{
		if (HotkeyLookupTable[i].KeyCode == hotkey)
		{
			return HotkeyLookupTable[i].StringRepresentation;
		}
	}
	
	return NULL;
}

// Retrieves the keycode of a specified hotkey string representation.
unsigned int KeycodeFromString(const String& stringRepresentation)
{
	for (unsigned int i = 0; i < sizeof(HotkeyLookupTable) / sizeof(HotkeyLookupTable[0]); i++)
	{
		if (HotkeyLookupTable[i].StringRepresentation == stringRepresentation)
		{
			return HotkeyLookupTable[i].KeyCode;
		}
	}
	
	return 0;
}

// The CryAddHotkeyWindow default constructor.
CryAddHotkeyWindow::CryAddHotkeyWindow(CrySearchHotKey* entry, const Image& icon) : CryDialogTemplate(icon)
{
	// If the dialog was created with a valid pointer, edit mode should be enabled.
	this->mAlterEntry = entry;
	
	this->Title(entry ? "Edit Hotkey" : "Add Hotkey").SetRect(0, 0, 425, 100);
	
	this->mOK <<= THISBACK(DialogOkay);
	this->mCancel <<= THISBACK(DialogCancel);
	
	*this
		<< this->mHotkeyActionDescription.SetLabel("Action:").LeftPos(5, 75).TopPos(5, 20)
		<< this->mHotkeyAction.Add("Refresh search results, changed value").Add("Refresh search results, unchanged value")
			.Add("Refresh search results, increased value").Add("Refresh search results, decreased value")
			.Add("Toggle Freeze/Thaw on all address table entries").HSizePos(80, 5).TopPos(5, 25)
		<< this->mHotkeyDescription.SetLabel("Hotkey").LeftPos(5, 75).TopPos(35, 25)
		<< this->mHotkey.HSizePos(80, 5).TopPos(35, 25)
		<< this->mOK.Ok().SetLabel("OK").RightPos(5, 70).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(80, 70).BottomPos(5, 25)
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

// The CryAddHotkeyWindow default destructor.
CryAddHotkeyWindow::~CryAddHotkeyWindow()
{
	
}

// Executed when the user accepts the dialog.
void CryAddHotkeyWindow::DialogOkay()
{
	// Collect user inputted data.
	const String& selectedKey = this->mHotkeyAction.GetValue();
	unsigned int key = KeycodeFromString(this->mHotkey.GetValue());
	SettingsFile* const settings = SettingsFile::GetInstance();
	const unsigned int hCount = settings->GetHotkeyCount();
	
	// Check if the specified hotkey already exists and if it's not being currently edited.
	for (unsigned int i = 0; i < hCount; i++)
	{
		const CrySearchHotKey& curKey = settings->GetHotkey(i);
		if ((curKey.Description == selectedKey || curKey.Key == key) && this->mAlterEntry != &curKey)
		{
			Prompt("Input Error", CtrlImg::error(), "The selected hotkey is already occupied. Please select a different key.", "OK");
			return;
		}
	}
	
	// If the alter entry pointer is valid, it should be edited.
	if (this->mAlterEntry)
	{
		this->mAlterEntry->Description = selectedKey;
		this->mAlterEntry->Key = key;
	}
	else
	{
		settings->AddHotkey(selectedKey, key);
	}
	
	this->Close();
}

// Executed when the dialog is closed.
void CryAddHotkeyWindow::DialogCancel()
{
	this->Close();
}