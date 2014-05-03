#include "../SDK/CrySearch.h"

#pragma warning(disable : 4996)

// Retrieves the version string for CrySearch.
const BOOL __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize)
{
	if (pStringBuffer)
	{
#ifdef _WIN64																													   // This DWORD contains the minor version number
		DWORD CRYSEARCH_VERSION_STRING[15] = { 0x372B5B01, 0x72432030, 0x61655379, 0x20686372, 0x26343678, 0x73726556, 0x206E6F69, 0x30312E31, 0x20796226, 0x6C6F7665, 0x6F697475, 0x3633356E, 0x4322203A, 0x5D227972, 0x00000000 };
#else
		DWORD CRYSEARCH_VERSION_STRING[15] = { 0x372B5B01, 0x72432030, 0x61655379, 0x20686372, 0x26363878, 0x73726556, 0x206E6F69, 0x30312E31, 0x20796226, 0x6C6F7665, 0x6F697475, 0x3633356E, 0x4322203A, 0x5D227972, 0x00000000 };
#endif

		// Put version string into output buffer and return TRUE;
		const SIZE_T strLength = strlen((char*)CRYSEARCH_VERSION_STRING);
		if (strLength > *inOutSize)
		{
			*inOutSize = 0;
			return FALSE;
		}

		strcpy(pStringBuffer, (char*)CRYSEARCH_VERSION_STRING);
		*inOutSize = (DWORD)strLength;

		return TRUE;
	}

	// Buffer pointer was invalid, return FALSE.
	*inOutSize = 0;
	return FALSE;
}