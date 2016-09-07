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
const bool __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize);

// Retrieves the major and minor version number for CrySearch. Both input parameters must be valid pointers.
void __stdcall CrySearchGetMajorMinorVersion(WORD* const pMajor, WORD* const pMinor);

// -------------------------------------------------------------------------------------------------

// Parses an exception code into a string representation for the user interface. Returns the string representation of the exception
// or 'Unknown Exception' if the exception code could not be parsed.
const char* ParseExceptionCode(const LONG excCode);

#ifdef __cplusplus
}
#endif