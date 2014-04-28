#include <Windows.h>

#ifdef __cplusplus
extern "C"
{
#endif

	void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue);
	const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal);
	const BOOL __stdcall IsI386Process(HANDLE procHandle);
	const int CryCreateExternalThread(HANDLE procHandle, const SIZE_T StartAddress, void* parameter, BOOL suspended, int* pThreadId);
	const char* CryGetThreadPriority(HANDLE hThread);

#ifdef __cplusplus
}
#endif