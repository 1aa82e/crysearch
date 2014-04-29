#include <Windows.h>

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

#ifdef __cplusplus
extern "C"
{
#endif

	void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue);
	const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal);
	void GetHandleObjectAccess(const DWORD type, const DWORD mask, char** const outBuffer, DWORD* const outSize);

#ifdef _WIN64
	__declspec(dllexport) void AlignPointer(DWORD_PTR* Address, const DWORD Boundary);
#endif

#ifdef __cplusplus
}
#endif