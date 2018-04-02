#include "../SDK/CrySearch.h"

#pragma warning(disable : 4996)

// Retrieves the version string for CrySearch.
const bool __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize)
{
#ifdef _WIN64																													   // This DWORD contains the minor version number
	DWORD CRYSEARCH_VERSION_STRING[15] = { 0x372B5B01, 0x72432030, 0x61655379, 0x20686372, 0x26343678, 0x73726556, 0x206E6F69, 0x20332E33, 0x20796226, 0x6C6F7665, 0x6F697475, 0x3633356E, 0x4322203A, 0x5D227972, 0x00000000 };
#else
	DWORD CRYSEARCH_VERSION_STRING[15] = { 0x372B5B01, 0x72432030, 0x61655379, 0x20686372, 0x26363878, 0x73726556, 0x206E6F69, 0x20332E33, 0x20796226, 0x6C6F7665, 0x6F697475, 0x3633356E, 0x4322203A, 0x5D227972, 0x00000000 };
#endif

	// We don't to write outside of the input buffer. Check if the buffer is large enough. Return FALSE and the necessary size if not.
	const SIZE_T strLength = strlen((char*)CRYSEARCH_VERSION_STRING);
	if (strLength > *inOutSize)
	{
		*inOutSize = 0;
		return false;
	}

	// Attempt to copy the about string to the input buffer.
	if (pStringBuffer)
	{
		strcpy(pStringBuffer, (char*)CRYSEARCH_VERSION_STRING);
		*inOutSize = (DWORD)strLength;
		return true;
	}

	// Buffer pointer was invalid, return FALSE.
	*inOutSize = 0;
	return false;
}

// Retrieves the major and minor version numbers for CrySearch.
void __stdcall CrySearchGetMajorMinorVersion(WORD* const pMajor, WORD* const pMinor)
{
	*pMajor = 3;
	*pMinor = 3;
}

// ---------------------------------------------------------------------------------------------------------

// Describes an exception that occurs inside CrySearch. May also be used to idenfity exceptions in other processes.
// Currently, CrySearch uses this structure internally to translate exception codes to human readable string representations.
typedef struct _ExceptionLookupTableEntry
{
	// Represents the exception code of an exception. This may be one of the codes described on the MSDN page for the
	// EXCEPTION_RECORD structure.
	DWORD ExceptionCode;

	// A string representation of the exception. The CrySearch library contains a lookup table with statically allocated 
	// string representations that will be matched to the specified exception code.
	char* ExceptionString;
} ExceptionLookupTableEntry;

// The lookup table for exceptions and their string representations.
const ExceptionLookupTableEntry ExceptionLookupTable[] =
{
	{ EXCEPTION_ACCESS_VIOLATION, "Access violation" },
	{ EXCEPTION_ARRAY_BOUNDS_EXCEEDED, "Array bounds exceeded" },
	{ EXCEPTION_DATATYPE_MISALIGNMENT, "Attempted to access misaligned data" },
	{ EXCEPTION_FLT_DENORMAL_OPERAND, "Denormal floating point operand" },
	{ EXCEPTION_FLT_DIVIDE_BY_ZERO, "Floating point division by zero" },
	{ EXCEPTION_FLT_INEXACT_RESULT, "Inexact floating point operation result" },
	{ EXCEPTION_FLT_INVALID_OPERATION, "Invalid floating point operation" },
	{ EXCEPTION_FLT_OVERFLOW, "Floating point overflow" },
	{ EXCEPTION_FLT_STACK_CHECK, "Floating point stack check" },
	{ EXCEPTION_FLT_UNDERFLOW, "Floating point underflow" },
	{ EXCEPTION_ILLEGAL_INSTRUCTION, "Attempted execution of illegal instruction" },
	{ EXCEPTION_IN_PAGE_ERROR, "Unable to access memory page" },
	{ EXCEPTION_INT_DIVIDE_BY_ZERO, "Attempted to divide integer by zero" },
	{ EXCEPTION_INT_OVERFLOW, "Integer overflow" },
	{ EXCEPTION_INVALID_DISPOSITION, "Invalid disposition of exception" },
	{ EXCEPTION_NONCONTINUABLE_EXCEPTION, "Attempted non-continuable execution" },
	{ EXCEPTION_PRIV_INSTRUCTION, "Attempted execution of priveleged instruction" },
	{ EXCEPTION_STACK_OVERFLOW, "Stack overflow" },
	{ DBG_CONTROL_C, "Ctrl + C was pressed (console interrupt)" }
};

// Parses an exception code into a string representation for the user interface.
const char* ParseExceptionCode(const LONG excCode)
{
	unsigned int i = 0;
	const unsigned int end = sizeof(ExceptionLookupTable) / sizeof(ExceptionLookupTable[0]);
	while (i < end)
	{
		if (ExceptionLookupTable[i].ExceptionCode == excCode)
		{
			return ExceptionLookupTable[i].ExceptionString;
		}

		++i;
	}

	// This shouldn't be able to happen but just in case.
	return "Unknown Exception";
}