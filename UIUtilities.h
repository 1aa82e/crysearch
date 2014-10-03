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

// Generates a string-style signature of disassembly to be used in C or C++ code.
String GenerateStringStyleSignature(const Vector<ArrayOfBytes*>& byteArrays, DWORD* outSigLength);

// Parameter definitions for the function below.
#define ARRAYTYPE_CPP		0
#define ARRAYTYPE_CSHARP	1

// Generates a byte array for either C# or C++ code files.
String GenerateByteArray(const Vector<ArrayOfBytes*>& byteArrays, const DWORD arrayType);

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

// Custom green text drawing for static addresses.
__declspec(selectany) struct StaticAddressDisplay : public Display
{
public:
	void Paint(Draw& w, const Rect& r, const Value& q, Color ink, Color paper, dword style) const
	{
		PaintBackground(w, r, q, ink, paper, style);
		w.DrawText(r.left, r.top, q.ToString(), StdFont(), Color(0, 160, 0));
	}
} GreenDisplayDrawInstance;

#endif
