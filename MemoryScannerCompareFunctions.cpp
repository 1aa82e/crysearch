#include "MemoryScanner.h"

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareGreater(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareGreater(const float& input, const float& expected)
{
	return ((int)input > (int)expected);
}

template <>
const bool CompareGreater(const double& input, const double& expected)
{
	return ((int)input > (int)expected);
}

template <typename T>
const bool CompareGreater(const T& input, const T& expected)
{
	return (input > expected);
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareSmaller(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareSmaller(const float& input, const float& expected)
{
	return ((int)input < (int)expected);
}

template <>
const bool CompareSmaller(const double& input, const double& expected)
{
	return ((int)input < (int)expected);
}

template <typename T>
const bool CompareSmaller(const T& input, const T& expected)
{
	return (input < expected);
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareEqual(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareEqual(const float& input, const float& expected)
{
	return (((int)input) == ((int)expected));
}

template <>
const bool CompareEqual(const double& input, const double& expected)
{
	return (((int)input) == ((int)expected));
}

template <typename T>
const bool CompareEqual(const T& input, const T& expected)
{
	return (input == expected);
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareInBetween(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareInBetween(const float& input, const float& expected)
{
	return ((int)input >= (int)expected && (int)input <= (int)(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->OuterScanValue);
}

template <>
const bool CompareInBetween(const double& input, const double& expected)
{
	return ((int)input >= (int)expected && (int)input <= (int)(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->OuterScanValue);
}

template <typename T>
const bool CompareInBetween(const T& input, const T& expected)
{
	// Is the input value at least expected and at most the second expected value?
	return (input >= expected && input <= (reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->OuterScanValue);
}

// ---------------------------------------------------------------------------------------------

template <typename T>
const bool CompareUnknownInitialValue(const T& input, const T& expected)
{
	// Unknown initial value should return everything that is found by the scanner.
	return true;
}

// ---------------------------------------------------------------------------------------------

// Compares ANSI and Unicode strings until a null character is found.
const bool CompareStringNullCharA(const char* input, const int inputLength, const char* expected, int* const outputLength)
{
	// Do the initial comparison of the input string.
	if (strncmp(input, expected, inputLength) == 0)
	{
		const char* iterator = input + inputLength;
		const int endIterator = STRING_MAX_UNTIL_NULL - inputLength;
		int i = 0;
		
		// Keep collecting characters until a NULL character is reached.
		while (*iterator != 0 && i < endIterator)
		{
			++iterator;
			++i;
		}
		*outputLength = i + inputLength;
		return true;
	}
	
	return false;
}

// Compares Unicode strings until a null character is found.
const bool CompareStringNullCharW(const wchar* input, const int inputLength, const wchar* expected, int* const outputLength)
{
	// Do the initial comparison of the input string.
	if (wcsncmp(input, expected, inputLength) == 0)
	{
		const wchar* iterator = input + inputLength;
		const int endIterator = STRING_MAX_UNTIL_NULL - inputLength;
		int i = 0;
		
		// Keep collecting characters until a NULL character is reached.
		while (*iterator != 0 && i < endIterator)
		{
			++iterator;
			++i;
		}
		*outputLength = i + inputLength;
		return true;
	}
	
	return false;
}

// ---------------------------------------------------------------------------------------------

// Template function instantiations to avoid linking errors.

template const bool CompareGreater<Byte>(const Byte& input, const Byte& expected);
template const bool CompareGreater<short>(const short& input, const short& expected);
template const bool CompareGreater<int>(const int& input, const int& expected);
template const bool CompareGreater<__int64>(const __int64& input, const __int64& expected);
template const bool CompareGreater<String>(const String& input, const String& expected);
template const bool CompareGreater<WString>(const WString& input, const WString& expected);

template const bool CompareSmaller<Byte>(const Byte& input, const Byte& expected);
template const bool CompareSmaller<short>(const short& input, const short& expected);
template const bool CompareSmaller<int>(const int& input, const int& expected);
template const bool CompareSmaller<__int64>(const __int64& input, const __int64& expected);
template const bool CompareSmaller<String>(const String& input, const String& expected);
template const bool CompareSmaller<WString>(const WString& input, const WString& expected);

template const bool CompareEqual<Byte>(const Byte& input, const Byte& expected);
template const bool CompareEqual<short>(const short& input, const short& expected);
template const bool CompareEqual<int>(const int& input, const int& expected);
template const bool CompareEqual<__int64>(const __int64& input, const __int64& expected);
template const bool CompareEqual<String>(const String& input, const String& expected);
template const bool CompareEqual<WString>(const WString& input, const WString& expected);

template const bool CompareInBetween<Byte>(const Byte& input, const Byte& expected);
template const bool CompareInBetween<short>(const short& input, const short& expected);
template const bool CompareInBetween<int>(const int& input, const int& expected);
template const bool CompareInBetween<__int64>(const __int64& input, const __int64& expected);
template const bool CompareInBetween<String>(const String& input, const String& expected);
template const bool CompareInBetween<WString>(const WString& input, const WString& expected);

template const bool CompareUnknownInitialValue<Byte>(const Byte& input, const Byte& expected);
template const bool CompareUnknownInitialValue<short>(const short& input, const short& expected);
template const bool CompareUnknownInitialValue<int>(const int& input, const int& expected);
template const bool CompareUnknownInitialValue<__int64>(const __int64& input, const __int64& expected);
template const bool CompareUnknownInitialValue<float>(const float& input, const float& expected);
template const bool CompareUnknownInitialValue<double>(const double& input, const double& expected);
template const bool CompareUnknownInitialValue<String>(const String& input, const String& expected);
template const bool CompareUnknownInitialValue<WString>(const WString& input, const WString& expected);
template const bool CompareUnknownInitialValue<ArrayOfBytes>(const ArrayOfBytes& input, const ArrayOfBytes& expected);