#include "UIUtilities.h"

// Converts a string representation for a data type size.
// Returns the size in bytes of the type of data.
const int GetDataSizeFromValueType(const String& type)
{
	if (type == "Byte")
	{
		return 1;
	}
	else if (type == "2 Bytes")
	{
		return 2;
	}
	else if (type == "4 Bytes")
	{
		return 4;
	}
	else if (type == "8 Bytes")
	{
		return 8;
	}
	else if (type == "Float")
	{
		return 4;
	}
	else if (type == "Double")
	{
		return 8;
	}
	else if (type == "String" || type == "WString" || type == "Array of Bytes")
	{
		return 1;
	}
	
	// Technically seen, this code path will never be reached. Tell the compiler to assume so.
	// Whenever the caller attempts to call this function with a parameter that is not listed in the conditional
	// listing, the behavior is undefined.
	__assume(0);
}

// Checks whether a tab page is opened in the CrySearch main window.
// Returns the index of the tab page if it is opened or -1 if it is not opened.
const int IsTabPageOpened(const TabCtrl& ctrl, const String& text)
{
	const int tabCount = ctrl.GetCount();
	for (int i = 0; i < tabCount; ++i)
	{
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
	int dataIndex = 0;
	const int inputLength = input.GetLength();
	Byte* const dataPtr = new Byte[inputLength];
	const char* iterator = input.Begin();
	const char* const endIterator = iterator + inputLength;
	
	while (iterator < endIterator)
	{
		if (*iterator == 0x20 || *iterator == 0x0)
		{
			++iterator;
		}
		else
		{
			dataPtr[dataIndex++] = getByte(iterator);
			iterator += 2;
		}
	}
	
	ArrayOfBytes aob;
	aob.Data = dataPtr;
	aob.Size = dataIndex;
	return aob;
}

const char ascstr[] = "0123456789ABCDEF";

// Converts a specified amount of bytes starting at buffer ending at buffer + length into its string representation.
// Returns a string containing the bytes inputted or an empty string if nothing was inputted.
// This function has been rigorously optimized because it produces a lot of samples, it gets called a lot.
String BytesToString(const Byte* const buffer, const unsigned int length)
{
	StringBuffer outString(length * 3 + 1);
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
		charCount = 0;
	}
	
	// Apply null terminator.
	retVal[ccBacking] = 0;
	return retVal;
}