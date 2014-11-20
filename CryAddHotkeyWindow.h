#ifndef _CrySearch_CryAddHotkeyWindow_h_
#define _CrySearch_CryAddHotkeyWindow_h_

#include "SettingsFile.h"
#include "CryDialogTemplate.h"

// Represents the structure for the lookup table from keycode to string representation.
struct HotkeyLookupTableEntry
{
	int KeyCode;
	char* StringRepresentation;
};

class CryAddHotkeyWindow : public CryDialogTemplate
{
private:
	CrySearchHotKey* mAlterEntry;
	
	Label mHotkeyActionDescription;
	DropList mHotkeyAction;
	Label mHotkeyDescription;
	DropList mHotkey;
	Button mOK;
	Button mCancel;
	
	void DialogOkay();
	void DialogCancel();
	
	typedef CryAddHotkeyWindow CLASSNAME;
public:
	CryAddHotkeyWindow(CrySearchHotKey* entry, const Image& icon);
	~CryAddHotkeyWindow();
};

#endif
