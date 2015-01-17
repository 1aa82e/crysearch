#include "CryVEHDebug.h"
#include "NativeAPI.h"
#include "../../CrySearchLibrary/SDK/CrySearch.h"

// Link to the CrySearch library for utility functions.
#ifdef _WIN64
	#pragma comment(lib, "../../CrySearchLibrary/Bin/x64/CrySearch64.lib")
#else
	#pragma comment(lib, "../../CrySearchLibrary/Bin/x86/CrySearch32.lib")
#endif

// Retrieves all threads loaded from a process. If the function fails, the output vector will have the same
// value as when it was used as input.
void EnumerateThreads(std::vector<DWORD>& threads)
{
	NTSTATUS returnVal;
	ULONG dataLength = 0x10000;
	PSYSTEM_PROCESS_INFORMATION procInfo = NULL;
	const DWORD processId = GetCurrentProcessId();
	NtQuerySystemInformationPrototype NtQuerySystemInformation = (NtQuerySystemInformationPrototype)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");

	// Query the system processes. If the call fails because of a length mismatch, recreate a bigger buffer and try again.
	do
	{
		procInfo = (PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(NULL, dataLength, MEM_COMMIT, PAGE_READWRITE);
		returnVal = NtQuerySystemInformation(SystemExtendedProcessInformation, procInfo, dataLength, &dataLength);
		if (returnVal == STATUS_INFO_LENGTH_MISMATCH)
		{
			// The length of the buffer was not sufficient. Expand the buffer before retrying.
			VirtualFree(procInfo, 0, MEM_RELEASE);
			dataLength *= 2;
		}
	} while (returnVal == STATUS_INFO_LENGTH_MISMATCH);

	if (returnVal == STATUS_SUCCESS)
	{
		PSYSTEM_PROCESS_INFORMATION curProc = procInfo;
		do
		{
			curProc = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)curProc + curProc->NextEntryOffset);

			// Iterate processes until the correct one is found.
			if ((int)curProc->UniqueProcessId == processId)
			{
				// Iterate threads of process.
				for (DWORD t = 0; t < curProc->NumberOfThreads; ++t)
				{
					PSYSTEM_EXTENDED_THREAD_INFORMATION curThread = &curProc->Threads[t];
					threads.push_back((int)curThread->ThreadInfo.ClientId.UniqueThread);
				}
			}
		} while (curProc->NextEntryOffset);
	}

	// Free heap allocated process information.
	VirtualFree(procInfo, 0, MEM_RELEASE);
}

// Hardware breakpoint routine that is executed when a hardware breakpoint should be set,
// disabled or removed. Function does not return any success indicator.
void BreakpointRoutine(CryBreakpoint* pHwbp, const DWORD threadId)
{
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);

	// Suspend thread in which to set breakpoint.
	if (!pHwbp->ProcessorTrapFlag && SuspendThread(hThread) == (DWORD)-1)
	{
		return;
	}

	void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
	PCONTEXT const ctx = (PCONTEXT)ctxBase;
	AlignPointer((DWORD_PTR*)&ctx, 8);
	memset(ctx, 0, sizeof(CONTEXT));
	ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, ctx))
	{
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		ResumeThread(hThread);
		return;
	}

	if (pHwbp->MustSetHardware)
	{
		unsigned long m_index = 0;

		// Find available debug register.
		for (; m_index < 4; ++m_index)
		{
#ifdef _WIN64
			if ((ctx->Dr7 & (1i64 << (m_index * 2))) == 0)
#else
			if ((ctx->Dr7 & (1 << (m_index * 2))) == 0)
#endif
			{
				break;
			}
		}

		// If this condition is true, all breakpoints are used, meaning the new breakpoint cannot be set.
		if (m_index >= 4)
		{
			VirtualFree(ctxBase, 0, MEM_RELEASE);
			ResumeThread(hThread);
			return;
		}

		// Set address in selected debug register.
		switch (m_index)
		{
		case 0:
			ctx->Dr0 = pHwbp->Address;
			pHwbp->DebugRegister = 0;
			break;
		case 1:
			ctx->Dr1 = pHwbp->Address;
			pHwbp->DebugRegister = 1;
			break;
		case 2:
			ctx->Dr2 = pHwbp->Address;
			pHwbp->DebugRegister = 2;
			break;
		case 3:
			ctx->Dr3 = pHwbp->Address;
			pHwbp->DebugRegister = 3;
			break;
		}

		CrySetBits(&ctx->Dr7, 16 + (m_index * 4), 2, pHwbp->HardwareType);
		CrySetBits(&ctx->Dr7, 18 + (m_index * 4), 2, pHwbp->HardwareSize);
		CrySetBits(&ctx->Dr7, m_index * 2, 1, 1);
	}
	else
	{
		switch (pHwbp->DebugRegister)
		{
		case 0:
			ctx->Dr0 = 0;
			break;
		case 1:
			ctx->Dr1 = 0;
			break;
		case 2:
			ctx->Dr2 = 0;
			break;
		case 3:
			ctx->Dr3 = 0;
			break;
		}

		ctx->Dr6 = 0;
		CrySetBits(&ctx->Dr7, pHwbp->DebugRegister * 2, 1, 0);
		pHwbp->DebugRegister = 0;
	}

	// Prepare context struct and set it into the threads context.
	if (!SetThreadContext(hThread, ctx))
	{
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		ResumeThread(hThread);
		return;
	}

	// Everything succeeded until now. resume thread and return.
	if (!pHwbp->ProcessorTrapFlag)
	{
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		ResumeThread(hThread);
	}

	VirtualFree(ctxBase, 0, MEM_RELEASE);
	CloseHandle(hThread);
}