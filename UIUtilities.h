#ifndef _CrySearch_UIUtilities_h_
#define _CrySearch_UIUtilities_h_

#include <CtrlLib/CtrlLib.h>

#include "MemoryScanner.h"
#include "CrySearchLibrary/SDK/CrySearch.h"

using namespace Upp;

// Contains functions that the user interface uses more than once. By defining a separate function
// the size of the generated code will be reduced.

ArrayOfBytes StringToBytes(const String& input);
String BytesToString(const Byte* const buffer, const unsigned int length);

// Checks whether a tab is opened in a specified tabctrl.
// Opened returns tab index;
// not opened returns -1.
const int IsTabPageOpened(const TabCtrl& ctrl, const String& text);

// Generates a random string to use as window title.
String GenerateRandomWindowTitle();

// Generates a string-style signature of disassembly to be used in C or C++ code.
String GenerateStringStyleSignature(const Vector<Byte>& byteArrays, DWORD* outSigLength);

// Parses the input data as string representation for the input value type.
String ValueAsStringInternal(const Byte* data, const CCryDataType type, const int size, const bool hex);

// Parses a 64-bit number and creates a hexadecimal representation.
String FormatInt64HexUpper(uint64 a);

// Parameter definitions for the function below.
#define ARRAYTYPE_CPP		0
#define ARRAYTYPE_CSHARP	1

// Generates a byte array for either C# or C++ code files.
String GenerateByteArray(const Vector<Byte>& bytes, const DWORD arrayType);

// Formats hexadecimal numbers as a string, including special cases such as 0x80000000.
String FormatHexadecimalIntSpecial(const uint32 value);

// Formats 64-bits hexadecimal numbers as a string, including special cases such as 0x8000000000000000.
String FormatHexadecimalIntSpecial64(const uint64 value);

// Formats decimal numbers as a string, including special cases such as 0x80000000.
String FormatIntSpecial(const uint32 value);

// Formats 64-bits hexadecimal numbers as a string, including special cases such as 0x8000000000000000.
String FormatIntSpecial64(const uint64 value);

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
