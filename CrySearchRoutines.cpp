#include "BackendGlobalDef.h"

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
	// Attempt lookup of NTDLL functions used throughout the program.
	const HMODULE ntdll = GetModuleHandle("ntdll.dll");
	this->NtQuerySystemInformation = (NtQuerySystemInformationPrototype)GetProcAddress(ntdll, "NtQuerySystemInformation");
	this->NtQueryInformationThread = (NtQueryInformationThreadPrototype)GetProcAddress(ntdll, "NtQueryInformationThread");
	this->NtQueryInformationProcess = (NtQueryInformationProcessPrototype)GetProcAddress(ntdll, "NtQueryInformationProcess");
	this->NtOpenProcess = (NtOpenProcessPrototype)GetProcAddress(ntdll, "NtOpenProcess");
	this->NtQueryObject = (NtQueryObjectPrototype)GetProcAddress(ntdll, "NtQueryObject");
	this->NtReadVirtualMemory = (NtReadVirtualMemoryPrototype)GetProcAddress(ntdll, "NtReadVirtualMemory");
	this->NtWriteVirtualMemory = (NtWriteVirtualMemoryPrototype)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	this->NtProtectVirtualMemory = (NtProtectVirtualMemoryPrototype)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	this->RtlCreateQueryDebugBuffer = (RtlCreateQueryDebugBufferPrototype)GetProcAddress(ntdll, "RtlCreateQueryDebugBuffer");
	this->RtlDestroyQueryDebugBuffer = (RtlDestroyQueryDebugBufferPrototype)GetProcAddress(ntdll, "RtlDestroyQueryDebugBuffer");
	this->RtlQueryProcessDebugInformation = (RtlQueryProcessDebugInformationPrototype)GetProcAddress(ntdll, "RtlQueryProcessDebugInformation");
	
	// Check if the lookup of any of the functions threw an error.
	this->wasError = !this->NtQuerySystemInformation || !this->NtQueryInformationThread || !this->NtQueryInformationProcess
		|| !this->NtOpenProcess || !this->NtQueryObject || !this->NtReadVirtualMemory || !this->NtWriteVirtualMemory
		|| !this->NtProtectVirtualMemory || !this->RtlCreateQueryDebugBuffer || !this->RtlDestroyQueryDebugBuffer
		|| !this->RtlQueryProcessDebugInformation;
	
	this->ReadMemoryRoutine = NULL;
	this->WriteMemoryRoutine = NULL;
	this->ProtectMemoryRoutine = NULL;
}

// It is possible that an error occured during the retrieval of one of the NTDLL functions. If
// this is the case, the user should at least be notified about possible undefined behavior.
const bool _CrySearchRoutines::ErrorOccured() const
{
	return this->wasError;
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

// Executes the selected memory writing routine.
const bool _CrySearchRoutines::CryWriteMemoryRoutine(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize) const
{
	return this->WriteMemoryRoutine(handle, addr, buffer, size, outSize);
}

// Executes the selected memory protection routine.
const bool _CrySearchRoutines::CryProtectMemoryRoutine(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess) const
{
	return this->ProtectMemoryRoutine(handle, addr, size, newAccess, oldAccess);
}

void _CrySearchRoutines::InitializeRoutines()
{
	SettingsFile* const settings = SettingsFile::GetInstance();
	// Assign correct memory reading routine.
	const int rpm = settings->GetReadMemoryRoutine();
	if (rpm == ROUTINE_READPROCESSMEMORY)
	{
		this->SetCrySearchReadMemoryRoutine(CryReadMemoryRoutine32);
	}
	else if (rpm == ROUTINE_NTREADVIRTUALMEMORY)
	{
		this->SetCrySearchReadMemoryRoutine(CryReadMemoryRoutineNt);
	}
	else if (rpm > 1)
	{
		Vector<CrySearchPlugin> plugins;
		mPluginSystem->GetPluginsByType(CRYPLUGIN_COREFUNC_OVERRIDE, plugins);
		const int rpm2 = rpm - 2;
		if (rpm2 < plugins.GetCount())
		{
			this->SetCrySearchReadMemoryRoutine((CryReadMemoryRoutineType)GetProcAddress(plugins[rpm2].BaseAddress, "CryReadMemoryRoutine"));
		}
	}
	
	// Assign the correct memory writing routine.
	const int wpm = settings->GetWriteMemoryRoutine();
	if (wpm == ROUTINE_WRITEPROCESSMEMORY)
	{
		this->SetCrySearchWriteMemoryRoutine(CryWriteMemoryRoutine32);
	}
	else if (wpm == ROUTINE_NTWRITEVIRTUALMEMORY)
	{
		this->SetCrySearchWriteMemoryRoutine(CryWriteMemoryRoutineNt);
	}
	else if (wpm > 1)
	{
		Vector<CrySearchPlugin> plugins;
		mPluginSystem->GetPluginsByType(CRYPLUGIN_COREFUNC_OVERRIDE, plugins);
		const int wpm2 = wpm - 2;
		if (wpm2 < plugins.GetCount())
		{
			this->SetCrySearchWriteMemoryRoutine((CryWriteMemoryRoutineType)GetProcAddress(plugins[wpm2].BaseAddress, "CryWriteMemoryRoutine"));
		}
	}
	
	// Assign the correct memory protection routine.
	const int pm = settings->GetProtectMemoryRoutine();
	if (pm == ROUTINE_VIRTUALPROTECTEX)
	{
		this->SetCrySearchProtectMemoryRoutine(CryProtectMemoryRoutine32);
	}
	else if (pm == ROUTINE_NTPROTECTVIRTUALMEMORY)
	{
		this->SetCrySearchProtectMemoryRoutine(CryProtectMemoryRoutineNt);
	}
	else if (pm > 1)
	{
		Vector<CrySearchPlugin> plugins;
		mPluginSystem->GetPluginsByType(CRYPLUGIN_COREFUNC_OVERRIDE, plugins);
		const int pm2 = pm - 2;
		if (pm2 < plugins.GetCount())
		{
			this->SetCrySearchProtectMemoryRoutine((CryProtectMemoryRoutineType)GetProcAddress(plugins[pm2].BaseAddress, "CryProtectMemoryRoutine"));
		}
	}
}