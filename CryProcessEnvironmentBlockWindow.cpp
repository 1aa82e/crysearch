#include "CryProcessEnvironmentBlockWindow.h"
#include "GlobalDef.h"
#include "NativeAPI.h"

CryProcessEnvironmentBlockWindow::CryProcessEnvironmentBlockWindow()
{
	this->Title("Process Information").SetRect(0, 0, 350, 300);
	
	this->mOk <<= THISBACK(DialogClose);
	this->mResetDebugFlag <<= THISBACK(ResetDebugFlag);
	
	*this
		<< this->mPEBWindowDescription.SetLabel("Viewing Process environment block").HSizePos(5, 5).TopPos(5, 20)
		<< this->mPEBInfo.HSizePos(5, 5).VSizePos(30, 30)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 20)
		<< this->mResetDebugFlag.SetLabel("Reset debug flag").LeftPos(5, 125).BottomPos(5, 20)
	;
	
	// Retrieve fields and build up window contents.
	this->Initialize();
}

CryProcessEnvironmentBlockWindow::~CryProcessEnvironmentBlockWindow()
{
	
}

void CryProcessEnvironmentBlockWindow::Initialize()
{
	// Start retrieving information from thread environment block.
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		ULONG_PTR PebBaseAddress;
		if (NtInternalFunctions.NtQueryInformationProcess(mMemoryScanner->GetHandle(), ProcessWow64Information, &PebBaseAddress, sizeof(ULONG_PTR), NULL) == STATUS_SUCCESS)
		{
			PEB32 peb;
			ReadProcessMemory(mMemoryScanner->GetHandle(), (void*)PebBaseAddress, &peb, sizeof(PEB32), NULL);
			
			this->pIsBeingDebuggedPtr = ((BYTE*)PebBaseAddress) + 0x2;
			
			this->mPEBInfo.AddColumn("Property", 65);
			this->mPEBInfo.AddColumn("Value", 35);
						
			this->mPEBInfo.Add("PEB Address", Format("%lX", (int)PebBaseAddress));
			this->mPEBInfo.Add("Inherited address space", Format("%X", peb.InheritedAddressSpace));
			this->mPEBInfo.Add("Read image file exec options", Format("%X", peb.ReadImageFileExecOptions));
			this->mPEBInfo.Add("Being debugged", Format("%X", peb.BeingDebugged));
			this->mPEBInfo.Add("Bitfield", Format("%X", peb.BitField));
			this->mPEBInfo.Add("Image base address", Format("%lX", (LONG_PTR)peb.ImageBaseAddress));
			this->mPEBInfo.Add("Loader data address", Format("%lX", (LONG_PTR)peb.LoaderData));
			this->mPEBInfo.Add("Process parameters", Format("%lX", (LONG_PTR)peb.ProcessParameters));
			this->mPEBInfo.Add("Subsystem data", Format("%lX", (LONG_PTR)peb.SubSystemData));
			this->mPEBInfo.Add("Process heap", Format("%lX", (LONG_PTR)peb.ProcessHeap));
			this->mPEBInfo.Add("Fast PEB lock", Format("%lX", (LONG_PTR)peb.FastPebLock));
			this->mPEBInfo.Add("ATL thunks list", Format("%lX", (LONG_PTR)peb.AtlThunkSListPtr));
			this->mPEBInfo.Add("IFEO key", Format("%lX", (LONG_PTR)peb.IFEOKey));
			this->mPEBInfo.Add("Environment update count", Format("%lX", (LONG_PTR)peb.EnvironmentUpdateCount));
			this->mPEBInfo.Add("Kernel Callback Table", Format("%lX", (LONG_PTR)peb.KernelCallbackTable));
			this->mPEBInfo.Add("ATL thunks list 32", Format("%lX", (LONG_PTR)peb.AtlThunkSListPtr32));
			this->mPEBInfo.Add("Api Set map pointer", Format("%lX", (LONG_PTR)peb.ApiSetMap));
			this->mPEBInfo.Add("TLS expansion counter", Format("%lX", (LONG_PTR)peb.TlsExpansionCounter));
			this->mPEBInfo.Add("TLS bitmap", Format("%lX", (LONG_PTR)peb.TlsBitmap));
			this->mPEBInfo.Add("Read-only shared memory base", Format("%lX", (LONG_PTR)peb.ReadOnlySharedMemoryBase));
			this->mPEBInfo.Add("Hotpatch information", Format("%lX", (LONG_PTR)peb.HotpatchInformation));
			this->mPEBInfo.Add("Read-only static server data", Format("%llX", (LONG_PTR)peb.ReadOnlyStaticServerData));
			this->mPEBInfo.Add("ANSI code page data", Format("%lX", (LONG_PTR)peb.AnsiCodePageData));
			this->mPEBInfo.Add("OEM code page data", Format("%lX", (LONG_PTR)peb.OemCodePageData));
			this->mPEBInfo.Add("Unicode case table data", Format("%lX", (LONG_PTR)peb.UnicodeCaseTableData));
			this->mPEBInfo.Add("Number of processors", Format("%lX", (LONG_PTR)peb.NumberOfProcessors));
			this->mPEBInfo.Add("NT global flag", Format("%lX", (LONG_PTR)peb.NtGlobalFlag));
			this->mPEBInfo.Add("Heap segment reserve", Format("%lX", (LONG_PTR)peb.HeapSegmentReserve));
			this->mPEBInfo.Add("Heap segment commit", Format("%lX", (LONG_PTR)peb.HeapSegmentCommit));
			this->mPEBInfo.Add("Heap decommit total free threshold", Format("%lX", (LONG_PTR)peb.HeapDeCommitTotalFreeThreshold));
			this->mPEBInfo.Add("Heap decommit free block threshold", Format("%lX", (LONG_PTR)peb.HeapDeCommitFreeBlockThreshold));
			this->mPEBInfo.Add("Number of heaps", Format("%i", (LONG_PTR)peb.NumberOfHeaps));
			this->mPEBInfo.Add("Maximum number of heaps", Format("%i", (LONG_PTR)peb.MaximumNumberOfHeaps));
			this->mPEBInfo.Add("Process heaps (void**)", Format("%lX", (LONG_PTR)peb.ProcessHeaps));
			this->mPEBInfo.Add("GDI shared handle table", Format("%lX", (LONG_PTR)peb.GdiSharedHandleTable));
			this->mPEBInfo.Add("Process starter helper", Format("%lX", (LONG_PTR)peb.ProcessStarterHelper));
			this->mPEBInfo.Add("GDI device context attribute list", Format("%lX", (LONG_PTR)peb.GdiDCAttributeList));
			this->mPEBInfo.Add("Loader Lock", Format("%lX", (LONG_PTR)peb.LoaderLock));
			this->mPEBInfo.Add("OS Major version", Format("%i", (LONG_PTR)peb.OSMajorVersion));
			this->mPEBInfo.Add("OS Minor version", Format("%i", (LONG_PTR)peb.OSMinorVersion));
			this->mPEBInfo.Add("OS build number", Format("%i", (LONG_PTR)peb.OSBuildNumber));
			this->mPEBInfo.Add("Post process init routine", Format("%lX", (LONG_PTR)peb.PostProcessInitRoutine));
			this->mPEBInfo.Add("Session ID", Format("%i", (LONG_PTR)peb.SessionId));
			this->mPEBInfo.Add("TLS expansion bitmap", Format("%lX", (LONG_PTR)peb.TlsExpansionBitmap));
			this->mPEBInfo.Add("App compatibility flags", Format("%llX", (LONG_PTR)peb.AppCompatFlags.QuadPart));
			this->mPEBInfo.Add("App compatibility flags user", Format("%llX", (LONG_PTR)peb.AppCompatFlagsUser.QuadPart));
			this->mPEBInfo.Add("Shim data", Format("%lX", (LONG_PTR)peb.pShimData));
			this->mPEBInfo.Add("App compatibility info", Format("%lX", (LONG_PTR)peb.AppCompatInfo));
			this->mPEBInfo.Add("CSD Version pointer", Format("%lX", (LONG_PTR)peb.CSDVersion.Buffer));
			this->mPEBInfo.Add("Activation context data", Format("%lX", (LONG_PTR)peb.ActivationContextData));
			this->mPEBInfo.Add("Assembly storage map", Format("%lX", (LONG_PTR)peb.ProcessAssemblyStorageMap));
			this->mPEBInfo.Add("System default activation context", Format("%lX", (LONG_PTR)peb.SystemDefaultActivationContextData));
			this->mPEBInfo.Add("Minimum stack commit", Format("%i", (LONG_PTR)peb.MinimumStackCommit));
			this->mPEBInfo.Add("FLS List, first element", Format("%lX", (LONG_PTR)peb.FlsListHead.Flink));
			this->mPEBInfo.Add("FLS bitmap bits", Format("%lX", (LONG_PTR)peb.FlsBitmapBits));
			this->mPEBInfo.Add("FLS high index", Format("%i", (LONG_PTR)peb.FlsHighIndex));
			this->mPEBInfo.Add("WER registration data", Format("%lX", (LONG_PTR)peb.WerRegistrationData));
			this->mPEBInfo.Add("WER ship assert pointer", Format("%lX", (LONG_PTR)peb.WerShipAssertPtr));
			this->mPEBInfo.Add("Context data", Format("%lX", (LONG_PTR)peb.pContextData));
			this->mPEBInfo.Add("Image header hash", Format("%lX", (LONG_PTR)peb.pImageHeaderHash));
			this->mPEBInfo.Add("Tracing flags", Format("%i", (LONG_PTR)peb.TracingFlags));
			this->mPEBInfo.Add("CSR server read-only shared memory", Format("%llX", (LONG_PTR)peb.CsrServerReadOnlySharedMemoryBase));
		}
		else
		{
			this->mPEBInfo.AddColumn("Error");
			this->mPEBInfo.Add("Failed to retrieve thread information");
		}
	}
	else
	{
		PROCESS_BASIC_INFORMATION tInfo;
		if (NtInternalFunctions.NtQueryInformationProcess(mMemoryScanner->GetHandle(), ProcessBasicInformation, &tInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL) == STATUS_SUCCESS)
		{
			PEB peb;
			ReadProcessMemory(mMemoryScanner->GetHandle(), tInfo.PebBaseAddress, &peb, sizeof(PEB), NULL);
			
			this->pIsBeingDebuggedPtr = ((BYTE*)tInfo.PebBaseAddress) + 0x2;
			
			this->mPEBInfo.AddColumn("Property", 65);
			this->mPEBInfo.AddColumn("Value", 35);
			
			this->mPEBInfo.Add("PEB Address", Format("%llX", tInfo.PebBaseAddress));
			this->mPEBInfo.Add("Inherited address space", Format("%X", peb.InheritedAddressSpace));
			this->mPEBInfo.Add("Read image file exec options", Format("%X", peb.ReadImageFileExecOptions));
			this->mPEBInfo.Add("Being debugged", Format("%X", peb.BeingDebugged));
			this->mPEBInfo.Add("Bitfield", Format("%X", peb.BitField));
			this->mPEBInfo.Add("Image base address", Format("%lX", (LONG_PTR)peb.ImageBaseAddress));
			this->mPEBInfo.Add("Loader data address", Format("%lX", (LONG_PTR)peb.LoaderData));
			this->mPEBInfo.Add("Process parameters", Format("%lX", (LONG_PTR)peb.ProcessParameters));
			this->mPEBInfo.Add("Subsystem data", Format("%lX", (LONG_PTR)peb.SubSystemData));
			this->mPEBInfo.Add("Process heap", Format("%lX", (LONG_PTR)peb.ProcessHeap));
			this->mPEBInfo.Add("Fast PEB lock", Format("%lX", (LONG_PTR)peb.FastPebLock));
			this->mPEBInfo.Add("ATL thunks list", Format("%lX", (LONG_PTR)peb.AtlThunkSListPtr));
			this->mPEBInfo.Add("IFEO key", Format("%lX", (LONG_PTR)peb.IFEOKey));
			this->mPEBInfo.Add("Environment update count", Format("%lX", (LONG_PTR)peb.EnvironmentUpdateCount));
			this->mPEBInfo.Add("Kernel Callback Table", Format("%lX", (LONG_PTR)peb.KernelCallbackTable));
			this->mPEBInfo.Add("ATL thunks list 32", Format("%lX", (LONG_PTR)peb.AtlThunkSListPtr32));
			this->mPEBInfo.Add("Api Set map pointer", Format("%lX", (LONG_PTR)peb.ApiSetMap));
			this->mPEBInfo.Add("TLS expansion counter", Format("%lX", (LONG_PTR)peb.TlsExpansionCounter));
			this->mPEBInfo.Add("TLS bitmap", Format("%lX", (LONG_PTR)peb.TlsBitmap));
			this->mPEBInfo.Add("Read-only shared memory base", Format("%lX", (LONG_PTR)peb.ReadOnlySharedMemoryBase));
			this->mPEBInfo.Add("Hotpatch information", Format("%lX", (LONG_PTR)peb.HotpatchInformation));
			this->mPEBInfo.Add("Read-only static server data", Format("%llX", (LONG_PTR)peb.ReadOnlyStaticServerData));
			this->mPEBInfo.Add("ANSI code page data", Format("%lX", (LONG_PTR)peb.AnsiCodePageData));
			this->mPEBInfo.Add("OEM code page data", Format("%lX", (LONG_PTR)peb.OemCodePageData));
			this->mPEBInfo.Add("Unicode case table data", Format("%lX", (LONG_PTR)peb.UnicodeCaseTableData));
			this->mPEBInfo.Add("Number of processors", Format("%lX", (LONG_PTR)peb.NumberOfProcessors));
			this->mPEBInfo.Add("NT global flag", Format("%lX", (LONG_PTR)peb.NtGlobalFlag));
			this->mPEBInfo.Add("Heap segment reserve", Format("%lX", (LONG_PTR)peb.HeapSegmentReserve));
			this->mPEBInfo.Add("Heap segment commit", Format("%lX", (LONG_PTR)peb.HeapSegmentCommit));
			this->mPEBInfo.Add("Heap decommit total free threshold", Format("%lX", (LONG_PTR)peb.HeapDeCommitTotalFreeThreshold));
			this->mPEBInfo.Add("Heap decommit free block threshold", Format("%lX", (LONG_PTR)peb.HeapDeCommitFreeBlockThreshold));
			this->mPEBInfo.Add("Number of heaps", Format("%i", (LONG_PTR)peb.NumberOfHeaps));
			this->mPEBInfo.Add("Maximum number of heaps", Format("%i", (LONG_PTR)peb.MaximumNumberOfHeaps));
			this->mPEBInfo.Add("Process heaps (void**)", Format("%lX", (LONG_PTR)peb.ProcessHeaps));
			this->mPEBInfo.Add("GDI shared handle table", Format("%lX", (LONG_PTR)peb.GdiSharedHandleTable));
			this->mPEBInfo.Add("Process starter helper", Format("%lX", (LONG_PTR)peb.ProcessStarterHelper));
			this->mPEBInfo.Add("GDI device context attribute list", Format("%lX", (LONG_PTR)peb.GdiDCAttributeList));
			this->mPEBInfo.Add("Loader Lock", Format("%lX", (LONG_PTR)peb.LoaderLock));
			this->mPEBInfo.Add("OS Major version", Format("%i", (LONG_PTR)peb.OSMajorVersion));
			this->mPEBInfo.Add("OS Minor version", Format("%i", (LONG_PTR)peb.OSMinorVersion));
			this->mPEBInfo.Add("OS build number", Format("%i", (LONG_PTR)peb.OSBuildNumber));
			this->mPEBInfo.Add("Post process init routine", Format("%lX", (LONG_PTR)peb.PostProcessInitRoutine));
			this->mPEBInfo.Add("TLS expansion bitmap", Format("%lX", (LONG_PTR)peb.TlsExpansionBitmap));
			this->mPEBInfo.Add("Session ID", Format("%i", (LONG_PTR)peb.SessionId));
			this->mPEBInfo.Add("TLS expansion bitmap", Format("%lX", (LONG_PTR)peb.TlsExpansionBitmap));
			this->mPEBInfo.Add("App compatibility flags", Format("%llX", (LONG_PTR)peb.AppCompatFlags.QuadPart));
			this->mPEBInfo.Add("App compatibility flags user", Format("%llX", (LONG_PTR)peb.AppCompatFlagsUser.QuadPart));
			this->mPEBInfo.Add("Shim data", Format("%lX", (LONG_PTR)peb.pShimData));
			this->mPEBInfo.Add("App compatibility info", Format("%lX", (LONG_PTR)peb.AppCompatInfo));
			this->mPEBInfo.Add("CSD Version pointer", Format("%lX", (LONG_PTR)peb.CSDVersion.Buffer));
			this->mPEBInfo.Add("Activation context data", Format("%lX", (LONG_PTR)peb.ActivationContextData));
			this->mPEBInfo.Add("Assembly storage map", Format("%lX", (LONG_PTR)peb.ProcessAssemblyStorageMap));
			this->mPEBInfo.Add("System default activation context", Format("%lX", (LONG_PTR)peb.SystemDefaultActivationContextData));
			this->mPEBInfo.Add("Minimum stack commit", Format("%i", (LONG_PTR)peb.MinimumStackCommit));
			this->mPEBInfo.Add("FLS List, first element", Format("%lX", (LONG_PTR)peb.FlsListHead.Flink));
			this->mPEBInfo.Add("FLS bitmap bits", Format("%lX", (LONG_PTR)peb.FlsBitmapBits));
			this->mPEBInfo.Add("FLS high index", Format("%i", (LONG_PTR)peb.FlsHighIndex));
			this->mPEBInfo.Add("WER registration data", Format("%lX", (LONG_PTR)peb.WerRegistrationData));
			this->mPEBInfo.Add("WER ship assert pointer", Format("%lX", (LONG_PTR)peb.WerShipAssertPtr));
			this->mPEBInfo.Add("Context data", Format("%lX", (LONG_PTR)peb.pContextData));
			this->mPEBInfo.Add("Image header hash", Format("%lX", (LONG_PTR)peb.pImageHeaderHash));
			this->mPEBInfo.Add("Tracing flags", Format("%i", (LONG_PTR)peb.TracingFlags));
			this->mPEBInfo.Add("CSR server read-only shared memory", Format("%llX", (LONG_PTR)peb.CsrServerReadOnlySharedMemoryBase));
		}
		else
		{
			this->mPEBInfo.AddColumn("Error");
			this->mPEBInfo.Add("Failed to retrieve thread information");
		}
	}
#else
	PROCESS_BASIC_INFORMATION tInfo;
	if (NtInternalFunctions.NtQueryInformationProcess(mMemoryScanner->GetHandle(), ProcessBasicInformation, &tInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL) == STATUS_SUCCESS)
	{
		PEB32 peb;
		ReadProcessMemory(mMemoryScanner->GetHandle(), tInfo.PebBaseAddress, &peb, sizeof(PEB32), NULL);
		
		this->pIsBeingDebuggedPtr = ((BYTE*)tInfo.PebBaseAddress) + 0x2;
		
		this->mPEBInfo.AddColumn("Property", 65);
		this->mPEBInfo.AddColumn("Value", 35);
		
		this->mPEBInfo.Add("PEB Address", Format("%lX", (int)tInfo.PebBaseAddress));
		this->mPEBInfo.Add("Inherited address space", Format("%X", peb.InheritedAddressSpace));
		this->mPEBInfo.Add("Read image file exec options", Format("%X", peb.ReadImageFileExecOptions));
		this->mPEBInfo.Add("Being debugged", Format("%X", peb.BeingDebugged));
		this->mPEBInfo.Add("Bitfield", Format("%X", peb.BitField));
		this->mPEBInfo.Add("Image base address", Format("%lX", (LONG_PTR)peb.ImageBaseAddress));
		this->mPEBInfo.Add("Loader data address", Format("%lX", (LONG_PTR)peb.LoaderData));
		this->mPEBInfo.Add("Process parameters", Format("%lX", (LONG_PTR)peb.ProcessParameters));
		this->mPEBInfo.Add("Subsystem data", Format("%lX", (LONG_PTR)peb.SubSystemData));
		this->mPEBInfo.Add("Process heap", Format("%lX", (LONG_PTR)peb.ProcessHeap));
		this->mPEBInfo.Add("Fast PEB lock", Format("%lX", (LONG_PTR)peb.FastPebLock));
		this->mPEBInfo.Add("ATL thunks list", Format("%lX", (LONG_PTR)peb.AtlThunkSListPtr));
		this->mPEBInfo.Add("IFEO key", Format("%lX", (LONG_PTR)peb.IFEOKey));
		this->mPEBInfo.Add("Environment update count", Format("%lX", (LONG_PTR)peb.EnvironmentUpdateCount));
		this->mPEBInfo.Add("Kernel Callback Table", Format("%lX", (LONG_PTR)peb.KernelCallbackTable));
		this->mPEBInfo.Add("ATL thunks list 32", Format("%lX", (LONG_PTR)peb.AtlThunkSListPtr32));
		this->mPEBInfo.Add("Api Set map pointer", Format("%lX", (LONG_PTR)peb.ApiSetMap));
		this->mPEBInfo.Add("TLS expansion counter", Format("%lX", (LONG_PTR)peb.TlsExpansionCounter));
		this->mPEBInfo.Add("TLS bitmap", Format("%lX", (LONG_PTR)peb.TlsBitmap));
		this->mPEBInfo.Add("Read-only shared memory base", Format("%lX", (LONG_PTR)peb.ReadOnlySharedMemoryBase));
		this->mPEBInfo.Add("Hotpatch information", Format("%lX", (LONG_PTR)peb.HotpatchInformation));
		this->mPEBInfo.Add("Read-only static server data", Format("%lX", (LONG_PTR)peb.ReadOnlyStaticServerData));
		this->mPEBInfo.Add("ANSI code page data", Format("%lX", (LONG_PTR)peb.AnsiCodePageData));
		this->mPEBInfo.Add("OEM code page data", Format("%lX", (LONG_PTR)peb.OemCodePageData));
		this->mPEBInfo.Add("Unicode case table data", Format("%lX", (LONG_PTR)peb.UnicodeCaseTableData));
		this->mPEBInfo.Add("Number of processors", Format("%lX", (LONG_PTR)peb.NumberOfProcessors));
		this->mPEBInfo.Add("NT global flag", Format("%lX", (LONG_PTR)peb.NtGlobalFlag));
		this->mPEBInfo.Add("Heap segment reserve", Format("%lX", (LONG_PTR)peb.HeapSegmentReserve));
		this->mPEBInfo.Add("Heap segment commit", Format("%lX", (LONG_PTR)peb.HeapSegmentCommit));
		this->mPEBInfo.Add("Heap decommit total free threshold", Format("%lX", (LONG_PTR)peb.HeapDeCommitTotalFreeThreshold));
		this->mPEBInfo.Add("Heap decommit free block threshold", Format("%lX", (LONG_PTR)peb.HeapDeCommitFreeBlockThreshold));
		this->mPEBInfo.Add("Number of heaps", Format("%i", (LONG_PTR)peb.NumberOfHeaps));
		this->mPEBInfo.Add("Maximum number of heaps", Format("%i", (LONG_PTR)peb.MaximumNumberOfHeaps));
		this->mPEBInfo.Add("Process heaps (void**)", Format("%lX", (LONG_PTR)peb.ProcessHeaps));
		this->mPEBInfo.Add("GDI shared handle table", Format("%lX", (LONG_PTR)peb.GdiSharedHandleTable));
		this->mPEBInfo.Add("Process starter helper", Format("%lX", (LONG_PTR)peb.ProcessStarterHelper));
		this->mPEBInfo.Add("GDI device context attribute list", Format("%lX", (LONG_PTR)peb.GdiDCAttributeList));
		this->mPEBInfo.Add("Loader Lock", Format("%lX", (LONG_PTR)peb.LoaderLock));
		this->mPEBInfo.Add("OS Major version", Format("%i", (LONG_PTR)peb.OSMajorVersion));
		this->mPEBInfo.Add("OS Minor version", Format("%i", (LONG_PTR)peb.OSMinorVersion));
		this->mPEBInfo.Add("OS build number", Format("%i", (LONG_PTR)peb.OSBuildNumber));
		this->mPEBInfo.Add("Post process init routine", Format("%lX", (LONG_PTR)peb.PostProcessInitRoutine));
		this->mPEBInfo.Add("TLS expansion bitmap", Format("%lX", (LONG_PTR)peb.TlsExpansionBitmap));
		this->mPEBInfo.Add("Session ID", Format("%i", (LONG_PTR)peb.SessionId));
		this->mPEBInfo.Add("TLS expansion bitmap", Format("%lX", (LONG_PTR)peb.TlsExpansionBitmap));
		this->mPEBInfo.Add("App compatibility flags", Format("%lX", (LONG_PTR)peb.AppCompatFlags.QuadPart));
		this->mPEBInfo.Add("App compatibility flags user", Format("%lX", (LONG_PTR)peb.AppCompatFlagsUser.QuadPart));
		this->mPEBInfo.Add("Shim data", Format("%lX", (LONG_PTR)peb.pShimData));
		this->mPEBInfo.Add("App compatibility info", Format("%lX", (LONG_PTR)peb.AppCompatInfo));
		this->mPEBInfo.Add("CSD Version pointer", Format("%lX", (LONG_PTR)peb.CSDVersion.Buffer));
		this->mPEBInfo.Add("Activation context data", Format("%lX", (LONG_PTR)peb.ActivationContextData));
		this->mPEBInfo.Add("Assembly storage map", Format("%lX", (LONG_PTR)peb.ProcessAssemblyStorageMap));
		this->mPEBInfo.Add("System default activation context", Format("%lX", (LONG_PTR)peb.SystemDefaultActivationContextData));
		this->mPEBInfo.Add("Minimum stack commit", Format("%i", (LONG_PTR)peb.MinimumStackCommit));
		this->mPEBInfo.Add("FLS List, first element", Format("%lX", (LONG_PTR)peb.FlsListHead.Flink));
		this->mPEBInfo.Add("FLS bitmap bits", Format("%lX", (LONG_PTR)peb.FlsBitmapBits));
		this->mPEBInfo.Add("FLS high index", Format("%i", (LONG_PTR)peb.FlsHighIndex));
		this->mPEBInfo.Add("WER registration data", Format("%lX", (LONG_PTR)peb.WerRegistrationData));
		this->mPEBInfo.Add("WER ship assert pointer", Format("%lX", (LONG_PTR)peb.WerShipAssertPtr));
		this->mPEBInfo.Add("Context data", Format("%lX", (LONG_PTR)peb.pContextData));
		this->mPEBInfo.Add("Image header hash", Format("%lX", (LONG_PTR)peb.pImageHeaderHash));
		this->mPEBInfo.Add("Tracing flags", Format("%i", (LONG_PTR)peb.TracingFlags));
		this->mPEBInfo.Add("CSR server read-only shared memory", Format("%lX", (LONG_PTR)peb.CsrServerReadOnlySharedMemoryBase));
	}
	else
	{
		this->mPEBInfo.AddColumn("Error");
		this->mPEBInfo.Add("Failed to retrieve process environment block");
	}
#endif
}

bool CryProcessEnvironmentBlockWindow::Key(dword key, int count)
{
	if (key == K_ESCAPE)
	{
		this->Close();
		return true;
	}
	
	return false;
}

void CryProcessEnvironmentBlockWindow::ResetDebugFlag()
{
	// Reset the debug flag.
	// Poke the address of the flag with a 0 value.
	BYTE pResetted = 0x0;
	if (!WriteProcessMemory(mMemoryScanner->GetHandle(), this->pIsBeingDebuggedPtr, &pResetted, sizeof(BYTE), NULL))
	{
		Prompt("PEB Error", CtrlImg::error(), "The flag could not be resetted.", "OK");
	}

	// Remove all columns and rows, and rebuild window contents.
	this->mPEBInfo.Reset();
	this->Initialize();
}

void CryProcessEnvironmentBlockWindow::DialogClose()
{
	this->Close();
}