#ifndef _CrySearch_CryAddHotkeyWindow_h_
#define _CrySearch_CryAddHotkeyWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"

// Represents the structure for the lookup table from keycode to string representation.
struct HotkeyLookupTableEntry
{
	int KeyCode;
	String StringRepresentation;
};

class CryAddHotkeyWindow sealed : public TopWindow
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
	
	virtual bool Key(dword key, int count);
	
	typedef CryAddHotkeyWindow CLASSNAME;
public:
	CryAddHotkeyWindow(CrySearchHotKey* entry);
	~CryAddHotkeyWindow();
};

#endif
