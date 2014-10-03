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

// Retrieves the human readable version string for CrySearch.
// Returns TRUE if function succeeded and FALSE otherwise.
// Input buffer must be a valid pointer with at least 'inOutSize' allocated bytes.
// inOutSize parameter will receive total amount of copied chars when function returns.
const BOOL __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize);

// Retrieves the major and minor version number for CrySearch.
// Both parameters must be writeable and valid pointers.
void __stdcall CrySearchGetMajorMinorVersion(WORD* const pMajor, WORD* const pMinor);

// -------------------------------------------------------------------------------------------------

// Describes an exception that occurs inside CrySearch. May also be used to idenfity exceptions in other processes.
typedef struct _ExceptionLookupTableEntry
{
	DWORD ExceptionCode;
	char* ExceptionString;
} ExceptionLookupTableEntry;

// Parses an exception code into a string representation for the user interface.
// Returns 'Unknown Exception' if the exception code could not be parsed to something existing.
const char* ParseExceptionCode(const LONG excCode);

#ifdef __cplusplus
}
#endif