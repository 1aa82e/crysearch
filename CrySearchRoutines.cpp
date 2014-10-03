#include "GlobalDef.h"

// ---------------------------------------------------------------------------------------------

const bool __stdcall CryReadMemoryRoutine32(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize)
{
	return !!ReadProcessMemory(handle, addr, buffer, size, outSize);
}

const bool __stdcall CryReadMemoryRoutineNt(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize)
{
	return CrySearchRoutines.NtReadVirtualMemory(handle, addr, buffer, size, outSize) == STATUS_SUCCESS;
}

const bool __stdcall CryWriteMemoryRoutine32(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize)
{
	return !!WriteProcessMemory(handle, addr, buffer, size, outSize);
}

const bool __stdcall CryWriteMemoryRoutineNt(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize)
{
	return CrySearchRoutines.NtWriteVirtualMemory(handle, addr, buffer, size, outSize) == STATUS_SUCCESS;
}

const bool __stdcall CryProtectMemoryRoutine32(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess)
{
	return !!VirtualProtectEx(handle, addr, size, newAccess, oldAccess);
}

const bool __stdcall CryProtectMemoryRoutineNt(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess)
{
	// NtProtectVirtualMemory calls are tricky, the address parameter and size parameter must be a pointer to the actual data.
	return CrySearchRoutines.NtProtectVirtualMemory(handle, &addr, (PULONG)&size, newAccess, oldAccess) == STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------------------------

_CrySearchRoutines::_CrySearchRoutines()
{
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	this->NtQuerySystemInformation = (NtQuerySystemInformationPrototype)GetProcAddress(ntdll, "NtQuerySystemInformation");
	this->NtQueryInformationThread = (NtQueryInformationThreadPrototype)GetProcAddress(ntdll, "NtQueryInformationThread");
	this->NtQueryInformationProcess = (NtQueryInformationProcessPrototype)GetProcAddress(ntdll, "NtQueryInformationProcess");
	this->NtOpenProcess = (NtOpenProcessPrototype)GetProcAddress(ntdll, "NtOpenProcess");
	this->NtQueryObject = (NtQueryObjectPrototype)GetProcAddress(ntdll, "NtQueryObject");
	this->NtReadVirtualMemory = (NtReadVirtualMemoryPrototype)GetProcAddress(ntdll, "NtReadVirtualMemory");
	this->NtWriteVirtualMemory = (NtWriteVirtualMemoryPrototype)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	this->NtProtectVirtualMemory = (NtProtectVirtualMemoryPrototype)GetProcAddress(ntdll, "NtProtectVirtualMemory");
}

void _CrySearchRoutines::SetCrySearchReadMemoryRoutine(CryReadMemoryRoutineType read)
{
	this->ReadMemoryRoutine = read;
}

void _CrySearchRoutines::SetCrySearchWriteMemoryRoutine(CryWriteMemoryRoutineType write)
{
	this->WriteMemoryRoutine = write;
}

void _CrySearchRoutines::SetCrySearchProtectMemoryRoutine(CryProtectMemoryRoutineType protect)
{
	this->ProtectMemoryRoutine = protect;
}

// Executes the selected memory reading routine.
const bool _CrySearchRoutines::CryReadMemoryRoutine(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize) const
{
	return this->ReadMemoryRoutine(handle, addr, buffer, size, outSize);
}

const bool _CrySearchRoutines::CryWriteMemoryRoutine(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize) const
{
	return this->WriteMemoryRoutine(handle, addr, buffer, size, outSize);
}

const bool _CrySearchRoutines::CryProtectMemoryRoutine(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess) const
{
	return this->ProtectMemoryRoutine(handle, addr, size, newAccess, oldAccess);
}

void _CrySearchRoutines::InitializeRoutines()
{
	// Assign correct memory reading routine.
	switch (GlobalSettingsInstance.GetReadMemoryRoutine())
	{
		case ROUTINE_READPROCESSMEMORY:
			this->SetCrySearchReadMemoryRoutine(CryReadMemoryRoutine32);
			break;
		case ROUTINE_NTREADVIRTUALMEMORY:
			this->SetCrySearchReadMemoryRoutine(CryReadMemoryRoutineNt);
			break;
	}
	
	// Assign the correct memory writing routine.
	switch (GlobalSettingsInstance.GetWriteMemoryRoutine())
	{
		case ROUTINE_WRITEPROCESSMEMORY:
			this->SetCrySearchWriteMemoryRoutine(CryWriteMemoryRoutine32);
			break;
		case ROUTINE_NTWRITEVIRTUALMEMORY:
			this->SetCrySearchWriteMemoryRoutine(CryWriteMemoryRoutineNt);
			break;
	}
	
	// Assign the correct memory protection routine.
	switch (GlobalSettingsInstance.GetProtectMemoryRoutine())
	{
		case ROUTINE_VIRTUALPROTECTEX:
			this->SetCrySearchProtectMemoryRoutine(CryProtectMemoryRoutine32);
			break;
		case ROUTINE_NTPROTECTVIRTUALMEMORY:
			this->SetCrySearchProtectMemoryRoutine(CryProtectMemoryRoutineNt);
			break;
	}
}