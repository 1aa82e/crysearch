#pragma once

/*
 *	CrySearch library include file
 *	evolution536, UnknownCheats, 2014
 *
 *	Include this file in your application to have all CrySearch library functions available.
 */

#include "UtilFunctions.h"
#include "ProcessCore.h"
#include "Plugin.h"

#ifdef __cplusplus
extern "C"
{
#endif

// Retrieves the human readable version string for CrySearch. The 'pStringBuffer' parameter must point to a pre-allocated
// buffer. The buffer must fit the size specified by the 'inOutSize' parameter. 512 bytes is the recommended input buffer size.
// If the 'inOutSize' parameter is a valid pointer that points to the value 0, the function will return FALSE and place the necessary
// buffer size in the 'inOutSize' parameter. If the buffer is of sufficient size, the function will copy the about string to the buffer
// and place the size of the buffer in the 'inOutSize' parameter. The function returns TRUE if function succeeded and FALSE otherwise.
const BOOL __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize);

// Retrieves the major and minor version number for CrySearch. Both input parameters must be valid pointers.
void __stdcall CrySearchGetMajorMinorVersion(WORD* const pMajor, WORD* const pMinor);

// -------------------------------------------------------------------------------------------------

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

// Parses an exception code into a string representation for the user interface. Returns the string representation of the exception
// or 'Unknown Exception' if the exception code could not be parsed.
const char* ParseExceptionCode(const LONG excCode);

#ifdef __cplusplus
}
#endif