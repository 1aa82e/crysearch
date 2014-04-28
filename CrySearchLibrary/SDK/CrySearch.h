/*
 *	CrySearch library include file
 *	evolution536, UnknownCheats, 2014
 *
 *	Include this file in your application to have all CrySearch library functions available.
 */

#include "UtilFunctions.h"

// Retrieves the human readable version string for CrySearch.
// Returns TRUE if function succeeded and FALSE otherwise.
// Input buffer must be a valid pointer with at least 'inOutSize' allocated bytes.
// inOutSize parameter will receive total amount of copied chars when function returns.
const BOOL __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize);