#ifndef _CrySearch_HandlePermissions_h_
#define _CrySearch_HandlePermissions_h_

// Conversion type definitions for GetHandleObjectAccess.
#define HANDLE_ACCESS_TYPE_FILE		0x1
#define HANDLE_ACCESS_TYPE_THREAD	0x2
#define HANDLE_ACCESS_TYPE_PROCESS	0x4
#define HANDLE_ACCESS_TYPE_REGKEY	0x8

// Safe buffer size definitions for GetHandleObjectAccess.
#define SAFE_BUFFER_SIZE_FILE		17
#define SAFE_BUFFER_SIZE_THREAD		12
#define SAFE_BUFFER_SIZE_PROCESS	13
#define SAFE_BUFFER_SIZE_REGKEY		11

// Conversion function for the access mask dissection.
#ifdef __cplusplus
extern "C"
#endif
void GetHandleObjectAccess(const DWORD type, const DWORD mask, char** const outBuffer, DWORD* const outSize);

#endif