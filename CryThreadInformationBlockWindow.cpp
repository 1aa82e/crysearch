#include "CryThreadInformationBlockWindow.h"
#include "GlobalDef.h"

CryThreadInformationBlockWindow::CryThreadInformationBlockWindow(const int threadId)
{
	this->Title("Thread Information").Sizeable().SetRect(0, 0, 320, 300);
	
	this->mOk <<= THISBACK(DialogClose);
	
	*this
		<< this->mThreadWindowDescription.SetLabel(Format("Viewing thread environment block for thread: %X", threadId)).HSizePos(5, 5).TopPos(5, 20)
		<< this->mThreadInfo.HSizePos(5, 5).VSizePos(30, 30)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 20)
	;
	
	// Start retrieving information from thread environment block.	
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);

	THREAD_BASIC_INFORMATION tInfo;
	if (NtInternalFunctions.NtQueryInformationThread(hThread, ThreadBasicInformation, &tInfo, sizeof(THREAD_BASIC_INFORMATION), NULL) == STATUS_SUCCESS)
	{
		this->mThreadInfo.AddColumn("Property", 60);
		this->mThreadInfo.AddColumn("Value", 40);
		
#ifdef _WIN64
		if (mMemoryScanner->IsX86Process())
		{
			TEB32 tib;
			
			// TEB32 is located at TebBaseAddress + 0x2000, cheat sheet. :+)
			ReadProcessMemory(mMemoryScanner->GetHandle(), (unsigned char*)tInfo.TebBaseAddress + 0x2000, &tib, sizeof(TEB32), NULL);
			
			this->mThreadInfo.Add("TEB Address", Format("%lX", (LONG_PTR)tib.NtTib.Self));
			this->mThreadInfo.Add("Current SEH frame", Format("%lX", (LONG_PTR)tib.NtTib.ExceptionList));
			this->mThreadInfo.Add("Base address of stack", Format("%lX", (LONG_PTR)tib.NtTib.StackBase));
			this->mThreadInfo.Add("Stack limit", Format("%lX", (LONG_PTR)tib.NtTib.StackLimit));
			this->mThreadInfo.Add("Subsystem TIB", Format("%lX", (LONG_PTR)tib.NtTib.SubSystemTib));
			this->mThreadInfo.Add("Fiber data / Version", Format("%lX", (LONG_PTR)tib.NtTib.FiberData));
			this->mThreadInfo.Add("Arbitrary user pointer", Format("%lX", (LONG_PTR)tib.NtTib.ArbitraryUserPointer));
			this->mThreadInfo.Add("Environment pointer", Format("%lX", (LONG_PTR)tib.EnvironmentPointer));
			this->mThreadInfo.Add("Current process ID", Format("%lX", (LONG_PTR)tib.ClientId.UniqueProcess));
			this->mThreadInfo.Add("Current thread ID", Format("%lX", (LONG_PTR)tib.ClientId.UniqueThread));
			this->mThreadInfo.Add("Active RPC handle", Format("%lX", (LONG_PTR)tib.ActiveRpcHandle));
			this->mThreadInfo.Add("TLS Pointer", Format("%lX", (LONG_PTR)tib.ThreadLocalStoragePointer));
			this->mThreadInfo.Add("PEB address", Format("%lX", (LONG_PTR)tib.ProcessEnvironmentBlock));
			this->mThreadInfo.Add("Last error value", Format("%lX", (LONG_PTR)tib.LastErrorValue));
			this->mThreadInfo.Add("Critical section count", Format("%lX", (LONG_PTR)tib.CountOfOwnedCriticalSections));
			this->mThreadInfo.Add("Address of CSR client thread", Format("%lX", (LONG_PTR)tib.CsrClientThread));
			this->mThreadInfo.Add("Win32 Thread info", Format("%lX", (LONG_PTR)tib.Win32ThreadInfo));
			this->mThreadInfo.Add("Current locale", Format("%lX", (LONG_PTR)tib.CurrentLocale));
			this->mThreadInfo.Add("FP software status register", Format("%lX", (LONG_PTR)tib.FpSoftwareStatusRegister));
			this->mThreadInfo.Add("Exception code", Format("%lX", (LONG_PTR)tib.ExceptionCode));
			this->mThreadInfo.Add("Activation context stack pointer", Format("%lX", (LONG_PTR)tib.ActivationContextStackPointer));
			this->mThreadInfo.Add("TX FS context", Format("%lX", (LONG_PTR)tib.TxFsContext));
			this->mThreadInfo.Add("Real process ID", Format("%lX", (LONG_PTR)tib.RealClientId.UniqueProcess));
			this->mThreadInfo.Add("Real thread ID", Format("%lX", (LONG_PTR)tib.RealClientId.UniqueThread));
			this->mThreadInfo.Add("GDI cached process handle", Format("%lX", (LONG_PTR)tib.GdiCachedProcessHandle));
			this->mThreadInfo.Add("GDI client process ID", Format("%lX", (LONG_PTR)tib.GdiClientPID));
			this->mThreadInfo.Add("GDI client thread ID", Format("%lX", (LONG_PTR)tib.GdiClientTID));
			this->mThreadInfo.Add("GDI thread locale info", Format("%lX", (LONG_PTR)tib.GdiThreadLocaleInfo));
			this->mThreadInfo.Add("Last status value", Format("%lX", (LONG_PTR)tib.LastStatusValue));
			this->mThreadInfo.Add("Deallocation stack pointer", Format("%lX", (LONG_PTR)tib.DeallocationStack));
			this->mThreadInfo.Add("TLS links list, first element", Format("%lX", (LONG_PTR)tib.TlsLinks.Flink));
			this->mThreadInfo.Add("VDM pointer", Format("%lX", (LONG_PTR)tib.Vdm));
			this->mThreadInfo.Add("Hard error mode", Format("%i", (LONG_PTR)tib.HardErrorMode));
			this->mThreadInfo.Add("Sub-process tab", Format("%lX", (LONG_PTR)tib.SubProcessTag));
			this->mThreadInfo.Add("ETW local data", Format("%lX", (LONG_PTR)tib.EtwLocalData));
			this->mThreadInfo.Add("ETW trace data", Format("%lX", (LONG_PTR)tib.EtwTraceData));
			this->mThreadInfo.Add("Winsock data", Format("%lX", (LONG_PTR)tib.WinSockData));
			this->mThreadInfo.Add("GDI batch count", Format("%i", (LONG_PTR)tib.GdiBatchCount));
			this->mThreadInfo.Add("Ideal processor value", Format("%i", (LONG_PTR)tib.IdealProcessorValue));
			this->mThreadInfo.Add("Guaranteed stack bytes", Format("%i", (LONG_PTR)tib.GuaranteedStackBytes));
			this->mThreadInfo.Add("Waiting on loader lock", Format("%i", (LONG_PTR)tib.WaitingOnLoaderLock));
			this->mThreadInfo.Add("Saved priority state", Format("%lX", (LONG_PTR)tib.SavedPriorityState));
			this->mThreadInfo.Add("Soft-patch pointer", Format("%lX", (LONG_PTR)tib.SoftPatchPtr1));
			this->mThreadInfo.Add("Thread pool data", Format("%lX", (LONG_PTR)tib.ThreadPoolData));
			this->mThreadInfo.Add("TLS expansion slots", Format("%lX", (LONG_PTR)tib.TlsExpansionSlots));
			this->mThreadInfo.Add("MUI generation", Format("%i", (LONG_PTR)tib.MuiGeneration));
			this->mThreadInfo.Add("Impersonation status", Format("%i", (LONG_PTR)tib.IsImpersonating));
			this->mThreadInfo.Add("NLS cache", Format("%lX", (LONG_PTR)tib.NlsCache));
			this->mThreadInfo.Add("Shim data", Format("%lX", (LONG_PTR)tib.pShimData));
			this->mThreadInfo.Add("Virtual heap affinity", Format("%i", (LONG_PTR)tib.HeapVirtualAffinity));
			this->mThreadInfo.Add("Current transaction handle", Format("%lX", (LONG_PTR)tib.CurrentTransactionHandle));
			this->mThreadInfo.Add("Pointer to active frame", Format("%lX", (LONG_PTR)tib.ActiveFrame));
			this->mThreadInfo.Add("FLS data", Format("%lX", (LONG_PTR)tib.FlsData));
			this->mThreadInfo.Add("Preferred languages", Format("%lX", (LONG_PTR)tib.PreferredLanguages));
			this->mThreadInfo.Add("User preferred languages", Format("%lX", (LONG_PTR)tib.UserPrefLanguages));
			this->mThreadInfo.Add("Merged preferred languages", Format("%lX", (LONG_PTR)tib.MergedPrefLanguages));
			this->mThreadInfo.Add("MUI impersonation", Format("%i", (LONG_PTR)tib.MuiImpersonation));
			this->mThreadInfo.Add("Cross-TEB flags", Format("%i", (LONG_PTR)tib.CrossTebFlags));
			this->mThreadInfo.Add("Same TEB flags", Format("%i", (LONG_PTR)tib.SameTebFlags));
			this->mThreadInfo.Add("TXN scope enter callback", Format("%lX", (LONG_PTR)tib.TxnScopeEnterCallback));
			this->mThreadInfo.Add("TXN scope exit callback", Format("%lX", (LONG_PTR)tib.TxnScopeExitCallback));
			this->mThreadInfo.Add("TXN scope context", Format("%lX", (LONG_PTR)tib.TxnScopeContext));
			this->mThreadInfo.Add("Lock count", Format("%i", (LONG_PTR)tib.LockCount));
			this->mThreadInfo.Add("Resource return value", Format("%lX", (LONG_PTR)tib.ResourceRetValue));
		}
		else
		{
			TEB tib;
			ReadProcessMemory(mMemoryScanner->GetHandle(), tInfo.TebBaseAddress, &tib, sizeof(TEB), NULL);
			
			this->mThreadInfo.Add("TEB Address", Format("%llX", (LONG_PTR)tib.NtTib.Self));
			this->mThreadInfo.Add("Current SEH frame", Format("%llX", (LONG_PTR)tib.NtTib.ExceptionList));
			this->mThreadInfo.Add("Base address of stack", Format("%llX", (LONG_PTR)tib.NtTib.StackBase));
			this->mThreadInfo.Add("Stack limit", Format("%llX", (LONG_PTR)tib.NtTib.StackLimit));
			this->mThreadInfo.Add("Subsystem TIB", Format("%llX", (LONG_PTR)tib.NtTib.SubSystemTib));
			this->mThreadInfo.Add("Fiber data / Version", Format("%llX", (LONG_PTR)tib.NtTib.FiberData));
			this->mThreadInfo.Add("Arbitrary user pointer", Format("%llX", (LONG_PTR)tib.NtTib.ArbitraryUserPointer));
			this->mThreadInfo.Add("Environment pointer", Format("%llX", (LONG_PTR)tib.EnvironmentPointer));
			this->mThreadInfo.Add("Current process ID", Format("%llX", (LONG_PTR)tib.ClientId.UniqueProcess));
			this->mThreadInfo.Add("Current thread ID", Format("%llX", (LONG_PTR)tib.ClientId.UniqueThread));
			this->mThreadInfo.Add("Active RPC handle", Format("%llX", (LONG_PTR)tib.ActiveRpcHandle));
			this->mThreadInfo.Add("TLS Pointer", Format("%llX", (LONG_PTR)tib.ThreadLocalStoragePointer));
			this->mThreadInfo.Add("PEB address", Format("%llX", (LONG_PTR)tib.ProcessEnvironmentBlock));
			this->mThreadInfo.Add("Last error value", Format("%llX", (LONG_PTR)tib.LastErrorValue));
			this->mThreadInfo.Add("Critical section count", Format("%llX", (LONG_PTR)tib.CountOfOwnedCriticalSections));
			this->mThreadInfo.Add("Address of CSR client thread", Format("%llX", (LONG_PTR)tib.CsrClientThread));
			this->mThreadInfo.Add("Win32 Thread info", Format("%llX", (LONG_PTR)tib.Win32ThreadInfo));
			this->mThreadInfo.Add("Current locale", Format("%llX", (LONG_PTR)tib.CurrentLocale));
			this->mThreadInfo.Add("FP software status register", Format("%llX", (LONG_PTR)tib.FpSoftwareStatusRegister));
			this->mThreadInfo.Add("Exception code", Format("%llX", (LONG_PTR)tib.ExceptionCode));
			this->mThreadInfo.Add("Activation context stack pointer", Format("%llX", (LONG_PTR)tib.ActivationContextStackPointer));
			this->mThreadInfo.Add("TX FS context", Format("%llX", (LONG_PTR)tib.TxFsContext));
			this->mThreadInfo.Add("Real process ID", Format("%llX", (LONG_PTR)tib.RealClientId.UniqueProcess));
			this->mThreadInfo.Add("Real thread ID", Format("%llX", (LONG_PTR)tib.RealClientId.UniqueThread));
			this->mThreadInfo.Add("GDI cached process handle", Format("%llX", (LONG_PTR)tib.GdiCachedProcessHandle));
			this->mThreadInfo.Add("GDI client process ID", Format("%llX", (LONG_PTR)tib.GdiClientPID));
			this->mThreadInfo.Add("GDI client thread ID", Format("%llX", (LONG_PTR)tib.GdiClientTID));
			this->mThreadInfo.Add("GDI thread locale info", Format("%llX", (LONG_PTR)tib.GdiThreadLocaleInfo));
			this->mThreadInfo.Add("Last status value", Format("%llX", (LONG_PTR)tib.LastStatusValue));
			this->mThreadInfo.Add("Deallocation stack pointer", Format("%llX", (LONG_PTR)tib.DeallocationStack));
			this->mThreadInfo.Add("TLS links list, first element", Format("%llX", (LONG_PTR)tib.TlsLinks.Flink));
			this->mThreadInfo.Add("VDM pointer", Format("%llX", (LONG_PTR)tib.Vdm));
			this->mThreadInfo.Add("Hard error mode", Format("%i", (LONG_PTR)tib.HardErrorMode));
			this->mThreadInfo.Add("Sub-process tab", Format("%llX", (LONG_PTR)tib.SubProcessTag));
			this->mThreadInfo.Add("ETW local data", Format("%llX", (LONG_PTR)tib.EtwLocalData));
			this->mThreadInfo.Add("ETW trace data", Format("%llX", (LONG_PTR)tib.EtwTraceData));
			this->mThreadInfo.Add("Winsock data", Format("%llX", (LONG_PTR)tib.WinSockData));
			this->mThreadInfo.Add("GDI batch count", Format("%i", (LONG_PTR)tib.GdiBatchCount));
			this->mThreadInfo.Add("Ideal processor value", Format("%i", (LONG_PTR)tib.IdealProcessorValue));
			this->mThreadInfo.Add("Guaranteed stack bytes", Format("%i", (LONG_PTR)tib.GuaranteedStackBytes));
			this->mThreadInfo.Add("Waiting on loader lock", Format("%i", (LONG_PTR)tib.WaitingOnLoaderLock));
			this->mThreadInfo.Add("Saved priority state", Format("%llX", (LONG_PTR)tib.SavedPriorityState));
			this->mThreadInfo.Add("Soft-patch pointer", Format("%llX", (LONG_PTR)tib.SoftPatchPtr1));
			this->mThreadInfo.Add("Thread pool data", Format("%llX", (LONG_PTR)tib.ThreadPoolData));
			this->mThreadInfo.Add("TLS expansion slots", Format("%llX", (LONG_PTR)tib.TlsExpansionSlots));
			this->mThreadInfo.Add("Deallocation B-store", Format("%llX", (LONG_PTR)tib.DeallocationBStore));
			this->mThreadInfo.Add("B-store limit", Format("%llX", (LONG_PTR)tib.BStoreLimit));
			this->mThreadInfo.Add("MUI generation", Format("%i", (LONG_PTR)tib.MuiGeneration));
			this->mThreadInfo.Add("Impersonation status", Format("%i", (LONG_PTR)tib.IsImpersonating));
			this->mThreadInfo.Add("NLS cache", Format("%llX", (LONG_PTR)tib.NlsCache));
			this->mThreadInfo.Add("Shim data", Format("%llX", (LONG_PTR)tib.pShimData));
			this->mThreadInfo.Add("Virtual heap affinity", Format("%i", (LONG_PTR)tib.HeapVirtualAffinity));
			this->mThreadInfo.Add("Current transaction handle", Format("%llX", (LONG_PTR)tib.CurrentTransactionHandle));
			this->mThreadInfo.Add("Pointer to active frame", Format("%llX", (LONG_PTR)tib.ActiveFrame));
			this->mThreadInfo.Add("FLS data", Format("%llX", (LONG_PTR)tib.FlsData));
			this->mThreadInfo.Add("Preferred languages", Format("%llX", (LONG_PTR)tib.PreferredLanguages));
			this->mThreadInfo.Add("User preferred languages", Format("%llX", (LONG_PTR)tib.UserPrefLanguages));
			this->mThreadInfo.Add("Merged preferred languages", Format("%llX", (LONG_PTR)tib.MergedPrefLanguages));
			this->mThreadInfo.Add("MUI impersonation", Format("%i", (LONG_PTR)tib.MuiImpersonation));
			this->mThreadInfo.Add("Cross-TEB flags", Format("%i", (LONG_PTR)tib.CrossTebFlags));
			this->mThreadInfo.Add("Same TEB flags", Format("%i", (LONG_PTR)tib.SameTebFlags));
			this->mThreadInfo.Add("TXN scope enter callback", Format("%llX", (LONG_PTR)tib.TxnScopeEnterCallback));
			this->mThreadInfo.Add("TXN scope exit callback", Format("%llX", (LONG_PTR)tib.TxnScopeExitCallback));
			this->mThreadInfo.Add("TXN scope context", Format("%llX", (LONG_PTR)tib.TxnScopeContext));
			this->mThreadInfo.Add("Lock count", Format("%i", (LONG_PTR)tib.LockCount));
			this->mThreadInfo.Add("Resource return value", Format("%llX", (LONG_PTR)tib.ResourceRetValue));
		}
#else
		TEB tib;
		ReadProcessMemory(mMemoryScanner->GetHandle(), tInfo.TebBaseAddress, &tib, sizeof(TEB32), NULL);
		
		this->mThreadInfo.Add("TEB Address", Format("%lX", (LONG_PTR)tib.NtTib.Self));
		this->mThreadInfo.Add("Current SEH frame", Format("%lX", (LONG_PTR)tib.NtTib.ExceptionList));
		this->mThreadInfo.Add("Base address of stack", Format("%lX", (LONG_PTR)tib.NtTib.StackBase));
		this->mThreadInfo.Add("Stack limit", Format("%lX", (LONG_PTR)tib.NtTib.StackLimit));
		this->mThreadInfo.Add("Subsystem TIB", Format("%lX", (LONG_PTR)tib.NtTib.SubSystemTib));
		this->mThreadInfo.Add("Fiber data / Version", Format("%lX", (LONG_PTR)tib.NtTib.FiberData));
		this->mThreadInfo.Add("Arbitrary user pointer", Format("%llX", (LONG_PTR)tib.NtTib.ArbitraryUserPointer));
		this->mThreadInfo.Add("Environment pointer", Format("%lX", (LONG_PTR)tib.EnvironmentPointer));
		this->mThreadInfo.Add("Current process ID", Format("%lX", (LONG_PTR)tib.ClientId.UniqueProcess));
		this->mThreadInfo.Add("Current thread ID", Format("%lX", (LONG_PTR)tib.ClientId.UniqueThread));
		this->mThreadInfo.Add("Active RPC handle", Format("%lX", (LONG_PTR)tib.ActiveRpcHandle));
		this->mThreadInfo.Add("TLS Pointer", Format("%lX", (LONG_PTR)tib.ThreadLocalStoragePointer));
		this->mThreadInfo.Add("PEB address", Format("%lX", (LONG_PTR)tib.ProcessEnvironmentBlock));
		this->mThreadInfo.Add("Last error value", Format("%lX", (LONG_PTR)tib.LastErrorValue));
		this->mThreadInfo.Add("Critical section count", Format("%lX", (LONG_PTR)tib.CountOfOwnedCriticalSections));
		this->mThreadInfo.Add("Address of CSR client thread", Format("%lX", (LONG_PTR)tib.CsrClientThread));
		this->mThreadInfo.Add("Win32 Thread info", Format("%lX", (LONG_PTR)tib.Win32ThreadInfo));
		this->mThreadInfo.Add("Current locale", Format("%lX", (LONG_PTR)tib.CurrentLocale));
		this->mThreadInfo.Add("FP software status register", Format("%lX", (LONG_PTR)tib.FpSoftwareStatusRegister));
		this->mThreadInfo.Add("Exception code", Format("%lX", (LONG_PTR)tib.ExceptionCode));
		this->mThreadInfo.Add("Activation context stack pointer", Format("%lX", (LONG_PTR)tib.ActivationContextStackPointer));
		this->mThreadInfo.Add("TX FS context", Format("%lX", (LONG_PTR)tib.TxFsContext));
		this->mThreadInfo.Add("Real process ID", Format("%lX", (LONG_PTR)tib.RealClientId.UniqueProcess));
		this->mThreadInfo.Add("Real thread ID", Format("%lX", (LONG_PTR)tib.RealClientId.UniqueThread));
		this->mThreadInfo.Add("GDI cached process handle", Format("%lX", (LONG_PTR)tib.GdiCachedProcessHandle));
		this->mThreadInfo.Add("GDI client process ID", Format("%lX", (LONG_PTR)tib.GdiClientPID));
		this->mThreadInfo.Add("GDI client thread ID", Format("%lX", (LONG_PTR)tib.GdiClientTID));
		this->mThreadInfo.Add("GDI thread locale info", Format("%lX", (LONG_PTR)tib.GdiThreadLocaleInfo));
		this->mThreadInfo.Add("Last status value", Format("%lX", (LONG_PTR)tib.LastStatusValue));
		this->mThreadInfo.Add("Deallocation stack pointer", Format("%lX", (LONG_PTR)tib.DeallocationStack));
		this->mThreadInfo.Add("TLS links list, first element", Format("%lX", (LONG_PTR)tib.TlsLinks.Flink));
		this->mThreadInfo.Add("VDM pointer", Format("%lX", (LONG_PTR)tib.Vdm));
		this->mThreadInfo.Add("Hard error mode", Format("%i", (LONG_PTR)tib.HardErrorMode));
		this->mThreadInfo.Add("Sub-process tab", Format("%lX", (LONG_PTR)tib.SubProcessTag));
		this->mThreadInfo.Add("ETW local data", Format("%lX", (LONG_PTR)tib.EtwLocalData));
		this->mThreadInfo.Add("ETW trace data", Format("%lX", (LONG_PTR)tib.EtwTraceData));
		this->mThreadInfo.Add("Winsock data", Format("%lX", (LONG_PTR)tib.WinSockData));
		this->mThreadInfo.Add("GDI batch count", Format("%i", (LONG_PTR)tib.GdiBatchCount));
		this->mThreadInfo.Add("Ideal processor value", Format("%i", (LONG_PTR)tib.IdealProcessorValue));
		this->mThreadInfo.Add("Guaranteed stack bytes", Format("%i", (LONG_PTR)tib.GuaranteedStackBytes));
		this->mThreadInfo.Add("Waiting on loader lock", Format("%i", (LONG_PTR)tib.WaitingOnLoaderLock));
		this->mThreadInfo.Add("Saved priority state", Format("%lX", (LONG_PTR)tib.SavedPriorityState));
		this->mThreadInfo.Add("Soft-patch pointer", Format("%lX", (LONG_PTR)tib.SoftPatchPtr1));
		this->mThreadInfo.Add("Thread pool data", Format("%lX", (LONG_PTR)tib.ThreadPoolData));
		this->mThreadInfo.Add("TLS expansion slots", Format("%lX", (LONG_PTR)tib.TlsExpansionSlots));
		this->mThreadInfo.Add("MUI generation", Format("%i", (LONG_PTR)tib.MuiGeneration));
		this->mThreadInfo.Add("Impersonation status", Format("%i", (LONG_PTR)tib.IsImpersonating));
		this->mThreadInfo.Add("NLS cache", Format("%lX", (LONG_PTR)tib.NlsCache));
		this->mThreadInfo.Add("Shim data", Format("%lX", (LONG_PTR)tib.pShimData));
		this->mThreadInfo.Add("Virtual heap affinity", Format("%i", (LONG_PTR)tib.HeapVirtualAffinity));
		this->mThreadInfo.Add("Current transaction handle", Format("%lX", (LONG_PTR)tib.CurrentTransactionHandle));
		this->mThreadInfo.Add("Pointer to active frame", Format("%lX", (LONG_PTR)tib.ActiveFrame));
		this->mThreadInfo.Add("FLS data", Format("%lX", (LONG_PTR)tib.FlsData));
		this->mThreadInfo.Add("Preferred languages", Format("%lX", (LONG_PTR)tib.PreferredLanguages));
		this->mThreadInfo.Add("User preferred languages", Format("%lX", (LONG_PTR)tib.UserPrefLanguages));
		this->mThreadInfo.Add("Merged preferred languages", Format("%lX", (LONG_PTR)tib.MergedPrefLanguages));
		this->mThreadInfo.Add("MUI impersonation", Format("%i", (LONG_PTR)tib.MuiImpersonation));
		this->mThreadInfo.Add("Cross-TEB flags", Format("%i", (LONG_PTR)tib.CrossTebFlags));
		this->mThreadInfo.Add("Same TEB flags", Format("%i", (LONG_PTR)tib.SameTebFlags));
		this->mThreadInfo.Add("TXN scope enter callback", Format("%lX", (LONG_PTR)tib.TxnScopeEnterCallback));
		this->mThreadInfo.Add("TXN scope exit callback", Format("%lX", (LONG_PTR)tib.TxnScopeExitCallback));
		this->mThreadInfo.Add("TXN scope context", Format("%lX", (LONG_PTR)tib.TxnScopeContext));
		this->mThreadInfo.Add("Lock count", Format("%i", (LONG_PTR)tib.LockCount));
		this->mThreadInfo.Add("Resource return value", Format("%lX", (LONG_PTR)tib.ResourceRetValue));
#endif
	}
	else
	{
		this->mThreadInfo.AddColumn("Error");
		this->mThreadInfo.Add("Failed to retrieve thread information");
	}
	
	CloseHandle(hThread);
}

CryThreadInformationBlockWindow::~CryThreadInformationBlockWindow()
{
	
}

void CryThreadInformationBlockWindow::DialogClose()
{
	this->Close();
}