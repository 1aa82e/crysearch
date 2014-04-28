/*#ifndef _CrySearch_DependencyChecker_h_
#define _CrySearch_DependencyChecker_h_

#include "depcheck_sdk/include/DepCheckSDK.h"

// Represents a dependency checker result.
// Use functions InitializeDepCheckResult and FreeDepCheckResult to handle the allocation and deallocation.
typedef struct _DEPCHECKRESULT
{
	LPWSTR SystemInformationString;
	// Should put dependency information here, but need documentation from l_m first. :)
} DEPCHECKRESULT, *PDEPCHECKRESULT;

// CrySearch dependency checker functions.
#ifdef __cplusplus
extern "C"
{
#endif

	void InitializeDepCheckResult(PDEPCHECKRESULT pResult);
	BOOL DependencyCheck(const char* fileName, PDEPCHECKRESULT pResult);
	void FreeDepCheckResult(PDEPCHECKRESULT pResult);
	
#ifdef __cplusplus
}
#endif

#endif*/