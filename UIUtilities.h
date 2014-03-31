#ifndef _CrySearch_UIUtilities_h_
#define _CrySearch_UIUtilities_h_

#include <CtrlLib/CtrlLib.h>

#include "MemoryScanner.h"

using namespace Upp;

// Contains functions that the user interface uses more than once. By defining a separate function
// the size of the generated code will be reduced.

ArrayOfBytes StringToBytes(const String& input);
String BytesToString(const Byte* const buffer, const unsigned int length);

// Checks whether a tab is opened in a specified tabctrl.
// Opened returns tab index;
// not opened returns -1.
const int IsTabPageOpened(const TabCtrl& ctrl, const String& text);

// Parses memory scanner address table entries and returns the correct data type size for the debugger.
const int GetDataSizeFromValueType(const String& type);

// Generates a random string to use as window title.
String GenerateRandomWindowTitle();

// Custom red text drawing for hooked imports.
__declspec(selectany) struct ImportAddressHookedDisplay : public Display
{
public:
	void Paint(Draw& w, const Rect& r, const Value& q, Color ink, Color paper, dword style) const
	{
		PaintBackground(w, r, q, ink, paper, style);
		w.DrawText(r.left, r.top, q.ToString(), StdFont(), LtRed());
	}
} RedDisplayDrawInstance;

#endif
