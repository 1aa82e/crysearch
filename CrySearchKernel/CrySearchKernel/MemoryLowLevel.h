#include <windef.h>
#include <ntddk.h>

const NTSTATUS CryReadProcessMemory(const int procId, const void* pAddress, void* const pOutBuffer, const DWORD readSize);