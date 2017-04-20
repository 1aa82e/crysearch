#include "UIUtilities.h"

// Checks whether a tab page is opened in the CrySearch main window.
// Returns the index of the tab page if it is opened or -1 if it is not opened.
const int IsTabPageOpened(const TabCtrl& ctrl, const String& text)
{
	const int tabCount = ctrl.GetCount();
	for (int i = 0; i < tabCount; ++i)
	{
		// Is the caption of the current tabpage equal to what we want to find?
		if (ctrl.GetItem(i).GetText() == text)
		{
			return i;
		}
	}
	
	return -1;
}

// Utility macros that convert a character representation to its value as byte.
#define INRANGE(x,a,b)		(x >= a && x <= b)
#define getBits(x)			(INRANGE((x&(~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xA) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x)			(getBits(x[0]) << 4 | getBits(x[1]))

// Converts a string representation of an AOB value to its ArrayOfBytes value.
// Returns a new ArrayOfBytes structure, which contains the represented bytes.
// If the input string is invalid or incomplete, the contents of the return value are undefined.
ArrayOfBytes StringToBytes(const String& input)
{
	// The input string may not have been concatenated correctly, making strlen the only valid way of length comparison.
	const int inputLength = (int)strlen(input.Begin());
	Byte* const dataPtr = new Byte[inputLength];
	const char* iterator = input.Begin();
	int dataIndex = 0;
	const char* const endIterator = iterator + inputLength;
	
	// Iterate through the input string.
	while (iterator < endIterator)
	{
		// Step over spaces.
		if (*iterator == 0x20 || *iterator == 0x0)
		{
			++iterator;
		}
		else
		{
			// Parse the current string represented byte.
			dataPtr[dataIndex++] = getByte(iterator);
			iterator += 2;
		}
	}
	
	return ArrayOfBytes(dataPtr, dataIndex);
}

const char ascstr[] = "0123456789ABCDEF";

// Converts a specified amount of bytes starting at buffer ending at buffer + length into its string representation.
// Returns a string containing the bytes inputted or an empty string if nothing was inputted.
// This function has been rigorously optimized because it produces a lot of samples. It used to be called a lot.
String BytesToString(const Byte* const buffer, const unsigned int length)
{
	if (!length)
	{
		return "";
	}

	StringBuffer outString(length * 4 + 1);
	char* outIterator = outString.Begin();
	const Byte* iterator = buffer;
	const Byte* const endIterator = iterator + length;
	
	while (iterator < endIterator)
	{
		// Get the string representation of the input byte.
		*outIterator++ = ascstr[(*iterator >> 4) & 0xF];
		*outIterator++ = ascstr[*iterator++ & 0xF];
		*outIterator++ = 0x20;
	}
	
	// Set a null terminator at the end of the string.
	if (iterator >= endIterator)
	{
		*(outIterator - 1) = 0;
	}
	
	// Set the output string length to the current length. If we don't do this, we will get trouble with the output string being used.
	outString.Strlen();

	return outString;
}

// Generates a random string to use as window title.
// Returns a string with between 5 and 30 random characters.
String GenerateRandomWindowTitle()
{
	// Get a random number between 5 and 30.
	DWORD charCount = Random(25) + 5;
	StringBuffer retVal(charCount + 1);
	char* outIterator = retVal.Begin();
	
	// Generate the string. ASCII characters from decimal 33 to 126 are used.
	const DWORD ccBacking = charCount;
	for (DWORD i = 0; i < ccBacking; ++i)
	{
		// Get random character code.
		charCount = Random(93) + 33;
		
		// Append the character to the output string.
		outIterator[i] = (char)charCount;
	}
	
	// Apply null terminator.
	retVal[ccBacking] = 0;
	return retVal;
}

// Generates a string-style signature of disassembly to be used in C or C++ code.
// Returns a string containing the signature. If the generation failed, the string is empty.
String GenerateStringStyleSignature(const Vector<Byte>& bytes)
{
	String retVal = BytesToString(bytes.Begin(), bytes.GetCount());
	
	// Remove the spaces and put FindPattern seperators in its place.
	retVal.Replace(" ", "");
	
	int counter = 0;
	while (counter < retVal.GetCount())
	{
		retVal.Insert(counter, "\\x");
		counter += 4;
	}
	
	return retVal;
}

// Generates a byte array for either C# or C++ programming language.
// Second parameter value ARRAYTYPE_CPP will generate C++ byte array. ARRAYTYPE_CSHARP or greater will generate C# byte array.
// Return value will contain generated byte array. Empty if failed.
String GenerateByteArray(const Vector<Byte>& bytes, const DWORD arrayType)
{
	String retVal = BytesToString(bytes.Begin(), bytes.GetCount());
	
	// Remove the spaces from the string and replace them with comma's.
	retVal.Replace(" ", ", ");
	
	// Insert '0x' prefixes for bytes.
	int counter = 0;
	while (counter < retVal.GetCount())
	{
		retVal.Insert(counter, "0x");
		counter += 6;
	}
	
	// Prefix and close the array declaration and return.
	retVal.Insert(0, arrayType == ARRAYTYPE_CPP ? "const BYTE sigArray[] = { " : "byte[] sigArray = new byte[] { ");
	retVal += " };";
	return retVal;
}

// Parses the input data as string representation for the input value type.
// Returns a newly constructed string containing the string representation.
// The size parameter is optional, and is only used for string, wstring and AOB types.
// If the function failed, the return value is an empty string.
String ValueAsStringInternal(const Byte* data, const CCryDataType type, const int size, const bool hex)
{
	switch (type)
	{
		case CRYDATATYPE_BYTE:
			return hex ? FormatHexadecimalIntSpecial(*(Byte*)data) : FormatIntSpecial(*(Byte*)data);
		case CRYDATATYPE_2BYTES:
			return hex ? FormatHexadecimalIntSpecial(*(short*)data) : FormatIntSpecial(*(short*)data);
		case CRYDATATYPE_4BYTES:
			return hex ? FormatHexadecimalIntSpecial(*(int*)data) : FormatIntSpecial(*(int*)data);
		case CRYDATATYPE_8BYTES:
			return hex ? FormatHexadecimalIntSpecial64(*(__int64*)data) : FormatIntSpecial64(*(__int64*)data);
		case CRYDATATYPE_FLOAT:
			return DblStr(*(float*)data);
		case CRYDATATYPE_DOUBLE:
			return DblStr(*(double*)data);
		case CRYDATATYPE_AOB:
			return BytesToString(data, size);
		case CRYDATATYPE_STRING:
			return String(data, size);
		case CRYDATATYPE_WSTRING:
			return WString((wchar*)data, size).ToString();
	}
	
	// Empty string is returned in case the type is invalid.
	return "";
}

// Parses a 64-bit number and creates a hexadecimal representation. Returns the hexadecimal
// representation in a string. The formatting returns upper-case characters.
String FormatInt64HexUpper(uint64 a)
{
	char b[50];
	char *p = b + 50;
	do
	{
		*--p = "0123456789ABCDEF"[a & 15];
		a >>= 4;
	}
	while(a);
	return String(p, b + 50);
}

// Formats hexadecimal numbers as a string, including special cases such as 0x80000000.
String FormatHexadecimalIntSpecial(const uint32 value)
{
	// Check for Null values, this doesn't get formatted properly.
	if (value == 0x80000000)
	{
		return "80000000";
	}
	else
	{
		// Normally return the formatted string.
		return FormatIntHexUpper(value, 0);
	}
}

// Formats 64-bits hexadecimal numbers as a string, including special cases such as 0x8000000000000000.
String FormatHexadecimalIntSpecial64(const uint64 value)
{
	// Check for Null values, this doesn't get formatted properly.
	if (value == 0x8000000000000000)
	{
		return "8000000000000000";
	}
	else
	{
		// Normally return the formatted string.
		return FormatInt64HexUpper(value);
	}
}

// Formats decimal numbers as a string, including special cases such as 0x80000000.
String FormatIntSpecial(const uint32 value)
{
	// Check for Null values, this doesn't get formatted properly.
	if (value == 0x80000000)
	{
		return "-2147483648";
	}
	else
	{
		// Normally return the formatted string.
		return IntStr(value);
	}
}

// Formats 64-bits hexadecimal numbers as a string, including special cases such as 0x8000000000000000.
String FormatIntSpecial64(const uint64 value)
{
	// Check for Null values, this doesn't get formatted properly.
	if (value == 0x8000000000000000)
	{
		return "-9223372036854775808";
	}
	else
	{
		// Normally return the formatted string.
		return IntStr64(value);
	}
}