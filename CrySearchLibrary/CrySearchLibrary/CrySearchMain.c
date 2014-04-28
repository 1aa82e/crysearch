#include "../SDK/CrySearch.h"

#ifdef _WIN64
	#define CRYSEARCH_VERSION_STRING "CrySearch x64 v1.10"
#else
	#define CRYSEARCH_VERSION_STRING "CrySearch x86 v1.10"
#endif

// Retrieves the version string for CrySearch.
const BOOL __stdcall CrySearchGetVersion(char* const pStringBuffer, DWORD* const inOutSize)
{
	if (pStringBuffer)
	{
		// Put version string into output buffer and return TRUE;
		const SIZE_T strLength = strlen(CRYSEARCH_VERSION_STRING);
		if (strLength > *inOutSize)
		{
			*inOutSize = 0;
			return FALSE;
		}

		memcpy(pStringBuffer, CRYSEARCH_VERSION_STRING, strLength);
		*inOutSize = (DWORD)strLength;

		return TRUE;
	}

	// Buffer pointer was invalid, return FALSE.
	*inOutSize = 0;
	return FALSE;
}