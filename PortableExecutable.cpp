#include "PortableExecutable.h"
#include "BackendGlobalDef.h"

// Defines seperately because the Windows SDK 7.1 headers do not yet include these two.
#define _WIN32_WINNT_WIN8                   0x0602
#define _WIN32_WINNT_WINBLUE                0x0603

#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#define EAT_ADDRESS_NOT_FOUND -1

// Checks whether a RVA points inside a section of the executable. Returns true if so and false if not.
const bool RVAPointsInsideSection(const DWORD rva)
{
	for (int i = 0; i < LoadedProcessPEInformation.ImageSections.GetCount(); ++i)
	{
		const Win32PESectionInformation& section = LoadedProcessPEInformation.ImageSections[i];
		if (rva > section.BaseAddress && rva < (section.BaseAddress + section.RawSectionSize))
		{
			return true;
		}
	}
	
	return false;
}

// -------------------------------------------------------------------------------------------------------------------------------
// Base class methods
// -------------------------------------------------------------------------------------------------------------------------------

// Default PE class constructor.
PortableExecutable::PortableExecutable()
{
	this->mProcessHandle = mMemoryScanner->GetHandle();
	this->mBaseAddress = mModuleManager->GetBaseAddress();
}

// Default PE class destructor. Virtual destructor, always use derived class' destructor to execute this one.
PortableExecutable::~PortableExecutable()
{
	LoadedProcessPEInformation.PEFields.Clear();
	LoadedProcessPEInformation.Reset();
	LoadedProcessPEInformation.ClearImportTable();
}

// Sets the base address.
void PortableExecutable::SetBaseAddress(const SIZE_T baseAddress)
{
	this->mBaseAddress = baseAddress;
}

// Retrieves the address of the Process Environment Block of the opened process.
// Returns the PEB base address or NULL if the address was not succesfully retrieved.
void* PortableExecutable::GetPebAddress() const
{
#ifdef WIN64
	if (mMemoryScanner->IsX86Process())
	{
		// If we run CrySearch x64 and we target an x86 process, we use NtQueryInformationProcess with a ULONG_PTR parameter.
		ULONG_PTR PebBaseAddress;
		if (CrySearchRoutines.NtQueryInformationProcess(this->mProcessHandle, ProcessWow64Information, &PebBaseAddress, sizeof(ULONG_PTR), NULL) == STATUS_SUCCESS)
		{
			return (void*)PebBaseAddress;
		}
	}
	else
	{
		// If we run CrySearch x64 and we target an x64 process, we use NtQueryInformationProcess with a PROCESS_BASIC_INFORMATION parameter.
		PROCESS_BASIC_INFORMATION tInfo;
		if (CrySearchRoutines.NtQueryInformationProcess(this->mProcessHandle, ProcessBasicInformation, &tInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL) == STATUS_SUCCESS)
		{
			return tInfo.PebBaseAddress;
		}
	}
#else
	// If we run CrySearch x86, we can only target an x86 process and we use NtQueryInformationProcess with a PROCESS_BASIC_INFORMATION parameter.
	PROCESS_BASIC_INFORMATION tInfo;
	if (CrySearchRoutines.NtQueryInformationProcess(this->mProcessHandle, ProcessBasicInformation, &tInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL) == STATUS_SUCCESS)
	{
		return tInfo.PebBaseAddress;
	}
#endif
	
	return NULL;
}

// Parses input machine type and adds the parsed value to the global inventory for UI display.
void PortableExecutable::ParseMachineType(const DWORD machineType) const
{
	switch (machineType)
	{
		case IMAGE_FILE_MACHINE_I386:
			LoadedProcessPEInformation.PEFields.Add("Machine Type", "i386");
			break;
		case IMAGE_FILE_MACHINE_IA64:
			LoadedProcessPEInformation.PEFields.Add("Machine Type", "ia64");
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			LoadedProcessPEInformation.PEFields.Add("Machine Type", "amd64");
			break;
		default:
			// This function is never called with other values than the three cases so we may assume a dead code path.
			__assume(0);
	}
}

// Parses input subsystem type and adds the parsed value to the global inventory for UI display.
void PortableExecutable::ParseSubsystemValue(const DWORD subSystem) const
{
	switch (subSystem)
	{
		case IMAGE_SUBSYSTEM_UNKNOWN:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Unknown");
			break;
		case IMAGE_SUBSYSTEM_NATIVE:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Native");
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Windows GUI");
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Windows CUI");
			break;
		case IMAGE_SUBSYSTEM_OS2_CUI:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "OS/2 CUI");
			break;
		case IMAGE_SUBSYSTEM_POSIX_CUI:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "POSIX_CUI");
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Windows CE CUI");
			break;
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "EFI");
			break;
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "EFI Boot Driver");
			break;
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "EFI Runtime Driver");
			break;
		case IMAGE_SUBSYSTEM_EFI_ROM:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "EFI ROM");
			break;
		case IMAGE_SUBSYSTEM_XBOX:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Xbox system");
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			LoadedProcessPEInformation.PEFields.Add("Subsystem", "Boot application");
			break;
		default:
			// Since the compiler cannot predict what value is in the Subsystem variable, we need to make the compiler assume there are no other values then stated.
			__assume(0);
	}
}

// This function retrieves all sections from a specified PE file. The NT header is provided to create flexibility.
// The input list is cleared before the retrieval is started.
void PortableExecutable::GetImageSectionsList(const IMAGE_SECTION_HEADER* pSecHeader, const DWORD numberOfSections, Vector<Win32PESectionInformation>& list) const
{
	list.Clear();
	
	// Iterate through sections and save them for application use.
	for (unsigned int i = 0; i < numberOfSections; ++i, ++pSecHeader)
	{
		// Sometimes PE files contain bogus sections at runtime due to packer activities. Remove bogus sections from the list.
		if (!pSecHeader->VirtualAddress)
		{
			continue;
		}
		
		// The name of a section can only be 8 characters long. A longer name has a different notation.
		// This is not taken into account because the chance of it appearing in an executable is very small.
		list.Add(Win32PESectionInformation((char*)pSecHeader->Name, pSecHeader->VirtualAddress, pSecHeader->Misc.VirtualSize == 0 ? pSecHeader->SizeOfRawData : pSecHeader->Misc.VirtualSize
			, pSecHeader->SizeOfRawData));
	}
}

// This function is declared seperately to reduce code in a few functions spreaded over this file.
// This increases the code readability even though the function will probably be inlined by the compiler.
wchar* PortableExecutable::InlineResolveApiSetSchema(const WString& str) const
{
	// Check which version of Windows is running. We need this to differentiate between ApiSetSchema versions.
	Tuple2<int, int> winver;
	if (GetInlineWindowsVersion(&winver))
	{
		// Call the correct ApiSetSchema parsing function.
		if (winver.a == 6)
		{
			if (winver.b == 4)
			{
				// Call the Windows 10 version of the parser.
				return this->ResolveApiSetSchemaMapping10(str, str.GetLength());
			}
			else if (winver.b > 2)
			{
				// Call the Windows 8(.1) version of the parser.
				return this->ResolveApiSetSchemaMappingEx(str, str.GetLength());
			}
			else
			{
				// Call the Windows 7 version of the parser.
				return this->ResolveApiSetSchemaMapping(str, str.GetLength());
			}
		}
		else if (winver.a == 10)
		{
			// Call the Windows 10 version of the parser.
			return this->ResolveApiSetSchemaMapping10(str, str.GetLength());
		}
	}
	
	return NULL;
}

// Resolves Windows 6.x ApiSetSchema redirections found in the IAT. Usually they redirect to a common Windows DLL like advapi32.dll.
// Returns the name of the redirected library, or NULL if the function failed. Beware that you still need to delete the buffer assigned to the return value!
wchar* PortableExecutable::ResolveApiSetSchemaMapping(const wchar* ApiSetSchemaDll, const DWORD Length) const
{
	// Retrieve PEB, the address of the map is there.
#ifdef _WIN64
	APISETMAP* const apiSetSchemaBase = (APISETMAP*)((PPEB)__readgsqword(0x60))->ApiSetMap;
#else
	APISETMAP* const apiSetSchemaBase = (APISETMAP*)((PPEB)__readfsdword(0x30))->ApiSetMap;
#endif
	
	Byte* const apiSetSchemaFileBuffer = (Byte*)apiSetSchemaBase;
	DLLHOSTDESCRIPTOR* pDescriptor = apiSetSchemaBase->descriptors;
	
	// Iterate through the descriptor structs.
	for (unsigned int i = 0; i < apiSetSchemaBase->NumberOfHosts; ++i, ++pDescriptor)
	{
		// Compare virtual API with input.
		if (_wcsnicmp(ApiSetSchemaDll, (wchar*)(apiSetSchemaFileBuffer + pDescriptor->OffsetDllString), Length) == 0)
		{
			DLLREDIRECTOR* const directorStruct = (DLLREDIRECTOR*)(apiSetSchemaFileBuffer + pDescriptor->OffsetDllRedirector);
			
			// Iterate redirections for this api set.
			REDIRECTION* pRedirectionDescriptor = directorStruct->Redirection;
			const wchar* const redirectionString = (wchar*)(apiSetSchemaFileBuffer + pRedirectionDescriptor->OffsetRedirection2);
			
			// Redirection is found, create buffer to return to the caller and copy the logical dll name into it.
			const DWORD wcsLength = pRedirectionDescriptor->RedirectionLength2 / 2;
			wchar* const nameBuffer = new wchar[wcsLength + 1];
			memcpy(nameBuffer, redirectionString, pRedirectionDescriptor->RedirectionLength2);
			
			// Set null terminator in the string, otherwise the result contains the redirected dll name but the rest is undefined.
			nameBuffer[wcsLength] = NULL;
			
			return nameBuffer;
		}
	}
	
	return NULL;
}

// Compatibility with Windows 8.1 ApiSetSchema v2 is implemented since v1.04 of CrySearch.
// Return value is the same as the PortableExecutable::ResolveApiSetSchemaMapping function.
wchar* PortableExecutable::ResolveApiSetSchemaMappingEx(const wchar* ApiSetSchemaDll, const DWORD Length) const
{
	// Retrieve PEB, the address of the map is there.
#ifdef _WIN64
	API_SET_NAMESPACE_ARRAY_V2* const apiSetSchemaBase = (API_SET_NAMESPACE_ARRAY_V2*)((PPEB)__readgsqword(0x60))->ApiSetMap;
#else
	API_SET_NAMESPACE_ARRAY_V2* const apiSetSchemaBase = (API_SET_NAMESPACE_ARRAY_V2*)((PPEB)__readfsdword(0x30))->ApiSetMap;
#endif
	
	Byte* const apiSetSchemaFileBuffer = (Byte*)apiSetSchemaBase;
	API_SET_NAMESPACE_ENTRY_V2* pDescriptor = apiSetSchemaBase->Array;
	
	// Iterate through the descriptor structs.
	for (unsigned int i = 0; i < apiSetSchemaBase->Count; ++i, ++pDescriptor)
	{
		// Compare virtual API with input.
		if (_wcsnicmp(ApiSetSchemaDll, (wchar*)(apiSetSchemaFileBuffer + pDescriptor->NameOffset), Length) == 0)
		{
			API_SET_VALUE_ARRAY_V2* const directorStruct = (API_SET_VALUE_ARRAY_V2*)(apiSetSchemaFileBuffer + pDescriptor->DataOffset);
			
			// Iterate redirections for this api set.
			API_SET_VALUE_ENTRY_V2* pRedirectionDescriptor = directorStruct->Array;
			const wchar* const redirectionString = (wchar*)(apiSetSchemaFileBuffer + pRedirectionDescriptor->ValueOffset);
				
			// Redirection is found, create buffer to return to the caller and copy the logical dll name into it.
			const DWORD wcsLength = pRedirectionDescriptor->ValueLength / 2;
			wchar* const nameBuffer = new wchar[wcsLength + 1];
			memcpy(nameBuffer, redirectionString, pRedirectionDescriptor->ValueLength);
			
			// Set null terminator in the string, otherwise the result contains the redirected dll name but the rest is undefined.
			nameBuffer[wcsLength] = NULL;
			
			return nameBuffer;
		}
	}
	
	return NULL;
}

// Compatibility with Windows 10 ApiSetSchema is implemented since v2.0 of CrySearch.
// Return value is the same as the PortableExecutable::ResolveApiSetSchemaMapping function.
wchar* PortableExecutable::ResolveApiSetSchemaMapping10(const wchar* ApiSetSchemaDll, const DWORD Length ) const
{
	// Retrieve PEB, the address of the map is there.
#ifdef _WIN64
	API_SET_NAMESPACE_ARRAY_10* const apiSetSchemaBase = (API_SET_NAMESPACE_ARRAY_10*)((PPEB)__readgsqword(0x60))->ApiSetMap;
#else
	API_SET_NAMESPACE_ARRAY_10* const apiSetSchemaBase = (API_SET_NAMESPACE_ARRAY_10*)((PPEB)__readfsdword(0x30))->ApiSetMap;
#endif
	
	Byte* const apiSetSchemaFileBuffer = (Byte*)apiSetSchemaBase;
	API_SET_NAMESPACE_ENTRY_10* pDescriptor = (API_SET_NAMESPACE_ENTRY_10*)(apiSetSchemaFileBuffer + apiSetSchemaBase->End);

	// Iterate through the descriptor structs.
	for (unsigned int i = 0; i < apiSetSchemaBase->Count; ++i, ++pDescriptor)
	{
		// Retrieve the data associated with the current ApiSet schema entry.
		API_SET_VALUE_ARRAY_10* const directorStruct = (API_SET_VALUE_ARRAY_10*)(apiSetSchemaFileBuffer + apiSetSchemaBase->Start + sizeof(API_SET_VALUE_ARRAY_10) * pDescriptor->Size);
		
		// Compare virtual API with input. We need to add 4 words to the pointer because in Windows 10, the API names are not truncated to 'ms-win...'.
		if (_wcsnicmp(ApiSetSchemaDll, (wchar*)(apiSetSchemaFileBuffer + directorStruct->NameOffset + 8), Length - 1) == 0)
		{
			// Iterate redirections for this api set.
			API_SET_VALUE_ENTRY_10* pRedirectionDescriptor = (API_SET_VALUE_ENTRY_10*)(apiSetSchemaFileBuffer + directorStruct->DataOffset);
			const wchar* const redirectionString = (wchar*)(apiSetSchemaFileBuffer + pRedirectionDescriptor->ValueOffset);
			
			// Redirection is found, create buffer to return to the caller and copy the logical dll name into it.
			const DWORD wcsLength = pRedirectionDescriptor->ValueLength / 2;
			wchar* const nameBuffer = new wchar[wcsLength + 1];
			memcpy(nameBuffer, redirectionString, pRedirectionDescriptor->ValueLength);
			
			// Set null terminator in the string, otherwise the result contains the redirected dll name but the rest is undefined.
			nameBuffer[wcsLength] = NULL;
			return nameBuffer;
		}
	}
	
	return NULL;
}

// Reads the COM directory from a PE file header. Most likely this is the .NET header.
// This function does not free the buffer pointed to by the parameter.
void PortableExecutable::GetDotNetDirectoryInformation(const IMAGE_DATA_DIRECTORY* const netHeader) const
{
	// Check if the executable contains a COM header.
	if (netHeader->VirtualAddress && netHeader->Size >= sizeof(IMAGE_COR20_HEADER))
	{
		// Read COR20 header from file.
		Byte* netDirBuffer = new Byte[netHeader->Size];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + netHeader->VirtualAddress), netDirBuffer, netHeader->Size, NULL);

		// Save version information from COR20 header.
		IMAGE_DATA_DIRECTORY mdDir;
		memcpy(&mdDir, &((IMAGE_COR20_HEADER*)netDirBuffer)->MetaData, sizeof(IMAGE_DATA_DIRECTORY));
		delete[] netDirBuffer;
		
		// Save the offset to the metadata header to allow dumping of .NET sections later.
		LoadedProcessPEInformation.DotNetInformation.MetadataHeaderOffset = mdDir.VirtualAddress;

		// Read metadata from header.
		netDirBuffer = new Byte[mdDir.Size];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + mdDir.VirtualAddress), netDirBuffer, mdDir.Size, NULL);
		
		// Dissect metadata. Since its a dynamic structure we cannot compile this into a struct.
		const DWORD vStrLength = *(DWORD*)(netDirBuffer + 12);
		const WORD streamCount = *(WORD*)(netDirBuffer + 18 + vStrLength);

		// Based on the stream count, dissect streams from the header.
		DWORD streamIterator = 0;
		for (const char* iterator = (char*)(netDirBuffer + 20 + vStrLength); streamIterator < streamCount; ++streamIterator)
		{
			// Get offset and size fields.
			const DWORD* const offsetPtr = (DWORD*)iterator;
			iterator += sizeof(DWORD);
			const DWORD* const sizePtr = (DWORD*)iterator;
			iterator += sizeof(DWORD);
			
			// Read the name of the stream.
			WORD str = 0;
			const char* const beginIterator = iterator;
			bool strEnded = false;
			while (1)
			{
				// First find the end of the string.
				if (!strEnded && *iterator == 0)
				{
					strEnded = true;
				}
				// Continue until the next 4 byte boundary is reached.
				else if (strEnded && ((SIZE_T)iterator % 4) == 0)
				{
					break;
				}

				++str;
				++iterator;
			}
			
			// String length was measured, now read it into a variable.
			Win32DotNetSectionInformation& newSect = LoadedProcessPEInformation.DotNetInformation.DotNetSections.Add();
			newSect.SectionName = String(beginIterator, str + 1);
			newSect.Offset = *offsetPtr;
			newSect.Size = *sizePtr;
		}

		delete[] netDirBuffer;
	}
}

// Resolves ApiSetSchema module names and returns a pointer to the resolved module.
const Win32ModuleInformation* PortableExecutable::GetResolvedModule(const Byte* bufferBase, int* const recurseIndex, const DWORD* funcPtr, const char* NameOrdinal) const
{
	String forwardedModName = (char*)(bufferBase + *funcPtr);
	*recurseIndex = forwardedModName.Find('.');

	if (ToLower(forwardedModName).StartsWith("api-ms-win"))
	{
		WString unicodeBuffer(forwardedModName);
		unicodeBuffer.Remove(0, 4);
		unicodeBuffer.Remove(unicodeBuffer.Find('.'), (int)strlen(NameOrdinal) + 1);

		const wchar* const outWString = this->InlineResolveApiSetSchema(unicodeBuffer);
		forwardedModName = WString(outWString).ToString();
		delete[] outWString;
	}

	const int dotIndex = forwardedModName.Find('.');
	if (dotIndex >= 0)
	{
		forwardedModName.Remove(dotIndex, forwardedModName.GetLength() - dotIndex);
		forwardedModName += ".dll";
	}

	return mModuleManager->FindModule(forwardedModName);
}

// -------------------------------------------------------------------------------------------------------------------------------
// PE32 class methods
// -------------------------------------------------------------------------------------------------------------------------------

// Default PE32 destructor. Base class destructor is virtual so this destructor is executed with the base's.
PortableExecutable32::~PortableExecutable32()
{
	
}

// Retrieves PE header information from the loaded process. Information is saved in global storage that has process lifetime.
// Note that IMAGE_NT_HEADERS and IMAGE_OPTIONAL_HEADER are explicitly defined as the 32 bit version. If compiled as 64 bit the structs differ.
void PortableExecutable32::GetExecutablePeInformation() const
{
	// Clear image sections before getting new ones.
	LoadedProcessPEInformation.Reset();
	
	// Read process memory into local buffer in order to load PE headers.
	Byte* moduleBuffer = new Byte[0x400];
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)this->mBaseAddress, moduleBuffer, 0x400, NULL);
	
	// Load PE headers.
	IMAGE_DOS_HEADER* const pDosHeader = (IMAGE_DOS_HEADER*)moduleBuffer;
	IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(moduleBuffer + pDosHeader->e_lfanew);

	// When the PE Headers are destroyed at runtime the pointer to the headers may run out of the buffer's bounds.
	if ((Byte*)pNTHeader > (moduleBuffer + 0x400))
	{
		delete[] moduleBuffer;
		LoadedProcessPEInformation.PEFields.Clear();
		return;
	}
	
	// The headers should be fine, proceed loading the optional and file header.
	const IMAGE_OPTIONAL_HEADER32* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;
	const IMAGE_FILE_HEADER* const pFileHeader = &(pNTHeader->FileHeader);
	
	// Retrieve the type of machine the PE executable can run on.
	this->ParseMachineType(pFileHeader->Machine);
	
	// Retrieve PE fields and add them to the map.
	LoadedProcessPEInformation.PEFields.Add("Number of sections", pFileHeader->NumberOfSections);
	LoadedProcessPEInformation.PEFields.Add("Size of optional header", Format("%X", pFileHeader->SizeOfOptionalHeader));
	LoadedProcessPEInformation.PEFields.Add("Pointer to symbol table", (int)pFileHeader->PointerToSymbolTable);
	LoadedProcessPEInformation.PEFields.Add("Number of symbols", (int)pFileHeader->NumberOfSymbols);
	LoadedProcessPEInformation.PEFields.Add("Image base", Format("%lX", (int)pOptionalHeader->ImageBase));

#ifndef _WIN64
	LoadedProcessPEInformation.PEFields.Add("Base of data", Format("%lX", (int)pOptionalHeader->BaseOfData));
#endif

	LoadedProcessPEInformation.PEFields.Add("Base of code", Format("%lX", (int)pOptionalHeader->BaseOfCode));
	LoadedProcessPEInformation.PEFields.Add("Address of entrypoint", Format("%lX", (int)pOptionalHeader->AddressOfEntryPoint));
	LoadedProcessPEInformation.PEFields.Add("Size of code", Format("%lX", (int)pOptionalHeader->SizeOfCode));
	LoadedProcessPEInformation.PEFields.Add("Size of initialized data", Format("%lX", (int)pOptionalHeader->SizeOfInitializedData));
	LoadedProcessPEInformation.PEFields.Add("Size of uninitialized data", Format("%lX", (int)pOptionalHeader->SizeOfUninitializedData));
	LoadedProcessPEInformation.PEFields.Add("Section alignment", Format("%lX", (int)pOptionalHeader->SectionAlignment));
	LoadedProcessPEInformation.PEFields.Add("File alignment", Format("%lX", (int)pOptionalHeader->FileAlignment));
	LoadedProcessPEInformation.PEFields.Add("Size of image", Format("%lX", (int)pOptionalHeader->SizeOfImage));
	LoadedProcessPEInformation.PEFields.Add("Size of headers", Format("%lX", (int)pOptionalHeader->SizeOfHeaders));
	LoadedProcessPEInformation.PEFields.Add("Checksum", Format("%lX", (int)pOptionalHeader->CheckSum));
	LoadedProcessPEInformation.PEFields.Add("Linker version", Format("%i.%i", pOptionalHeader->MajorLinkerVersion, pOptionalHeader->MinorLinkerVersion));
	LoadedProcessPEInformation.PEFields.Add("OS version", Format("%i.%i", pOptionalHeader->MajorOperatingSystemVersion, pOptionalHeader->MinorOperatingSystemVersion));
	LoadedProcessPEInformation.PEFields.Add("Image version", Format("%i.%i", pOptionalHeader->MajorImageVersion, pOptionalHeader->MinorImageVersion));
	LoadedProcessPEInformation.PEFields.Add("Subsystem version", Format("%i.%i", pOptionalHeader->MajorSubsystemVersion, pOptionalHeader->MinorSubsystemVersion));
	LoadedProcessPEInformation.PEFields.Add("Number of data directories", Format("%lX", (int)pOptionalHeader->NumberOfRvaAndSizes));
	
	// Parse the last general property value of the PE header, save the section values and destroy the buffer.
	this->ParseSubsystemValue(pOptionalHeader->Subsystem);
	const DWORD sectionCount = pNTHeader->FileHeader.NumberOfSections;
	const DWORD sectionSizeBytes = sizeof(IMAGE_SECTION_HEADER) * sectionCount;
	const IMAGE_SECTION_HEADER* const firstSectionPtr = (IMAGE_SECTION_HEADER*)(this->mBaseAddress + ((Byte*)IMAGE_FIRST_SECTION(pNTHeader) - moduleBuffer));
	
	// Get the COM header from the PE file.
	this->GetDotNetDirectoryInformation(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]);
	
	// Delete the allocated buffer to move on to the section enumeration.
	delete[] moduleBuffer;
	
	// Attempt to load the sections inside the PE file.
	moduleBuffer = new Byte[sectionSizeBytes];
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, firstSectionPtr, moduleBuffer, sectionSizeBytes, NULL);
	this->GetImageSectionsList((IMAGE_SECTION_HEADER*)moduleBuffer, sectionCount, LoadedProcessPEInformation.ImageSections);
	delete[] moduleBuffer;
}

// Retrieves the address of a function in the export table of a module. Address can be returned for function by name or ordinal.
// Returns the address of the function, created from the module base address added by the function RVA.
// If the function is not found, the return value is 0xFFFFFFFF.
SIZE_T PortableExecutable32::GetAddressFromExportTable(const AddrStruct* addr, const char* NameOrdinal, bool IsOrdinal) const
{
	if (addr->ExportDirectory->AddressOfNameOrdinals)
	{
		int ResurseDotIndex = 0;
		const DWORD* funcAddrPtr = NULL;
		
		for (unsigned int i = 0; i < addr->ExportDirectory->NumberOfFunctions; ++i)
		{
			const WORD* const ordValue = (WORD*)((addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNameOrdinals) + (i * sizeof(WORD)));

			if (IsOrdinal)
			{
				bool found = false;

				// Compare ordinal values without magic bitoperations!
				if ((addr->ExportDirectory->Base + *ordValue) == *reinterpret_cast<WORD*>(&NameOrdinal))
				{
					funcAddrPtr = (DWORD*)((addr->BufferBaseAddress + addr->ExportDirectory->AddressOfFunctions) + (sizeof(DWORD) * *ordValue));
					found = true;
				}
				
				// Skip the entry if it is not found.
				if (!found || ((Byte*)funcAddrPtr < addr->BufferBaseAddress || (Byte*)funcAddrPtr > addr->BufferEndAddress))
				{
					continue;
				}
				
				if (*funcAddrPtr > addr->DirectoryAddress->VirtualAddress && *funcAddrPtr < (addr->DirectoryAddress->VirtualAddress + addr->DirectoryAddress->Size))
				{
					const Win32ModuleInformation* modBaseAddr = this->GetResolvedModule(addr->BufferBaseAddress, &ResurseDotIndex, funcAddrPtr, NameOrdinal);
					
					// Sometimes infinite redirecting causes stack overflowing. Terminate this sequence by returning not found.
					if (!modBaseAddr || (SIZE_T)addr->BaseAddress == modBaseAddr->BaseAddress)
					{
						return EAT_ADDRESS_NOT_FOUND;
					}
						
					Byte* const dllBuffer = new Byte[0x400];
			        CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)modBaseAddr->BaseAddress, dllBuffer, 0x400, NULL);
			        
			        const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
					IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
			
			        delete[] dllBuffer;
			            
			        Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
			        CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(modBaseAddr->BaseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
					
					Byte* const bufBase = exportDirectoryBuffer - dataDir.VirtualAddress;
					AddrStruct addrStruct((Byte*)modBaseAddr->BaseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
						, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);
			            
					SIZE_T forwardedAddress = this->GetAddressFromExportTable(&addrStruct, (char*)(SIZE_T)ScanInt((char*)(addr->BufferBaseAddress + *funcAddrPtr + ResurseDotIndex + 2), NULL, 10), true);
					delete[] exportDirectoryBuffer;
					return forwardedAddress;
				}

				return (SIZE_T)(addr->BaseAddress + *funcAddrPtr);
			}
			else
			{
				const DWORD* const stringPtr = (DWORD*)((addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNames) + (i * sizeof(DWORD)));
				const char* const functionName = (char*)(addr->BufferBaseAddress + *stringPtr);
				
				const size_t strlength = strlen(NameOrdinal);
				if ((functionName > (char*)addr->BufferBaseAddress + addr->DirectoryAddress->VirtualAddress && (functionName + strlength + 1) < (char*)addr->BufferEndAddress) && memcmp(NameOrdinal, functionName, strlength) == 0)
				{
					funcAddrPtr = (DWORD*)((addr->BufferBaseAddress + addr->ExportDirectory->AddressOfFunctions) + (sizeof(DWORD) * *ordValue));
					if (*funcAddrPtr > addr->DirectoryAddress->VirtualAddress && *funcAddrPtr < (addr->DirectoryAddress->VirtualAddress + addr->DirectoryAddress->Size))
					{
						const Win32ModuleInformation* modBaseAddr = this->GetResolvedModule(addr->BufferBaseAddress, &ResurseDotIndex, funcAddrPtr, NameOrdinal);
						
						if (!modBaseAddr || (SIZE_T)addr->BaseAddress == modBaseAddr->BaseAddress)
						{
							return EAT_ADDRESS_NOT_FOUND;
						}
						
						Byte* const dllBuffer = new Byte[0x400];
			            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)modBaseAddr->BaseAddress, dllBuffer, 0x400, NULL);
			           
			            const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
						IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
			
			            delete[] dllBuffer;
			            
			            Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
			            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(modBaseAddr->BaseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
						
						Byte* const bufBase = exportDirectoryBuffer - dataDir.VirtualAddress;
						AddrStruct addrStruct((Byte*)modBaseAddr->BaseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
							, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);
			            
						SIZE_T forwardedAddress = this->GetAddressFromExportTable(&addrStruct, (char*)(addr->BufferBaseAddress + *funcAddrPtr + ResurseDotIndex + 1), false);
						delete[] exportDirectoryBuffer;
						return forwardedAddress;
					}

					return (SIZE_T)(addr->BaseAddress + *funcAddrPtr);
				}
			}
		}
	}
	
	return EAT_ADDRESS_NOT_FOUND;
}

// Attempts to retrieve function name associated to ordinal import from the export table of the loaded module.
// Returns a pointer to the function name if it exists. If the function is not found, the return value is NULL.
const char* PortableExecutable32::GetOrdinalFunctionNameFromExportTable(const AddrStruct* addr, const WORD ordinal) const
{
	const WORD* const ordinals = (WORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNameOrdinals);
	
	for (unsigned int i = 0; i < addr->ExportDirectory->NumberOfFunctions; ++i)
	{
		if ((addr->ExportDirectory->Base + ordinals[i]) == ordinal)
		{
			const DWORD* const stringPtr = (DWORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNames + i * sizeof(DWORD));
			const Byte* const absStringPtr = (Byte*)(addr->BufferBaseAddress + *stringPtr);
			
			// Make sure the string points inside of the buffer. Scrambled EAT would crash the application.
			if (absStringPtr > (addr->BufferBaseAddress + addr->DirectoryAddress->Size) && absStringPtr < addr->BufferEndAddress)
			{
				return (const char*)absStringPtr;
			}
		}
	}
	
	return NULL;
}

// Retrieves the import table from the PE header of the loaded process. This information is stored in the global storage that has process lifetime.
// Note that IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER, IMAGE_THUNK_DATA and SIZE_T are explicitly defined as the 32 bit version. If compiled as 64 bit the structs differ.
void PortableExecutable32::GetImportAddressTable() const
{
	// Read process memory into local buffer in order to load IAT.
	Byte* const moduleBuffer = new Byte[0x400];
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)this->mBaseAddress, moduleBuffer, 0x400, NULL);
	
	const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);

	// The PE Headers are not valid, the pointer runs outside the bounds of the buffer.
	if ((Byte*)pNTHeader > (moduleBuffer + 0x400))
	{
		delete[] moduleBuffer;
		return;
	}

	const IMAGE_OPTIONAL_HEADER32* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;
	
	unsigned int counter = 0;
	IMAGE_IMPORT_DESCRIPTOR pDesc;
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (counter * sizeof(IMAGE_IMPORT_DESCRIPTOR))), &pDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);

	while (pDesc.FirstThunk && pDesc.Name != 0xFFFF)
	{
		// Read DLL name from import descriptor entry.
		char dllName[48];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(pDesc.Name + this->mBaseAddress), dllName, 48, NULL);
        
        // Add new import descriptor to the table.
        ImportTableDescriptor& impDesc = LoadedProcessPEInformation.ImportAddressTable.Add();
        impDesc.ModuleName = dllName;
        
        // Get base address and length of desired DLL, and look up the function foreign name in the export table of that DLL.
        const Win32ModuleInformation* modBaseAddr = NULL;
		if (ToLower(dllName).StartsWith("api-ms-win"))
		{
			// Windows 6.x ApiSetSchema redirection detected, resolve the redirection.
			WString unicodeBuffer(dllName);
			unicodeBuffer.Remove(0, 4);
			unicodeBuffer.Remove(unicodeBuffer.GetLength() - 4, 4);
			
			const wchar* const outWString = this->InlineResolveApiSetSchema(unicodeBuffer);
			if (outWString)
			{
				WString redirectedDll = outWString;
				delete[] outWString;
			
				modBaseAddr = mModuleManager->FindModule(redirectedDll.ToString());
				impDesc.LogicalBaseAddress = modBaseAddr ? modBaseAddr->BaseAddress : 0;
			}
		}
		else
		{
			modBaseAddr = mModuleManager->FindModule(dllName);
			impDesc.LogicalBaseAddress = 0;
		}
        
        if (modBaseAddr)
        {
            Byte* const dllBuffer = new Byte[0x400];
            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)modBaseAddr->BaseAddress, dllBuffer, 0x400, NULL);
           
            const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
			IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

            delete[] dllBuffer;
            
            Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(modBaseAddr->BaseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
            
			Byte* const bufBase = (exportDirectoryBuffer - dataDir.VirtualAddress);
			AddrStruct addrStruct((Byte*)modBaseAddr->BaseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
				, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);

			IMAGE_THUNK_DATA32 thunk;
			unsigned int count = 0;

			do
			{
				// Read current thunk into local memory.
				CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pDesc.OriginalFirstThunk + count * sizeof(DWORD)), &thunk, sizeof(IMAGE_THUNK_DATA32), NULL);

				ImportAddressTableEntry funcEntry;

				// Check for 32-bit ordinal magic flag.
				if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					funcEntry.Ordinal = IMAGE_ORDINAL32(thunk.u1.Ordinal);
					funcEntry.Hint = 0;

					if (addrStruct.ExportDirectory->AddressOfNames)
					{
						funcEntry.FunctionName = this->GetOrdinalFunctionNameFromExportTable(&addrStruct, funcEntry.Ordinal);
					}
				}
				else
				{
					// Read function name from thunk data.
					char funcName[96];
					CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + thunk.u1.AddressOfData), funcName, 96, NULL);

					// Set ordinal value to 0, read function name and WORD sized hint from the first two read bytes sequence.
					funcEntry.Ordinal = 0;
					funcEntry.Hint = *(WORD*)funcName;
					funcEntry.FunctionName = funcName + sizeof(WORD);
				}

				// In a rare occasion the ordinal bit-flag is already removed. In this case the ordinal should be detected by section awareness.
				if (funcEntry.FunctionName.IsEmpty() && !RVAPointsInsideSection(thunk.u1.Ordinal))
				{
					funcEntry.Ordinal = (WORD)thunk.u1.Ordinal;
					funcEntry.Hint = 0;
					
					if (addrStruct.ExportDirectory->AddressOfNames)
					{
						funcEntry.FunctionName = this->GetOrdinalFunctionNameFromExportTable(&addrStruct, funcEntry.Ordinal);
					}
				}
				
				// If the function name is empty even after ordinal resolving, the function has no name. Give it an automated name.
				if (funcEntry.FunctionName.IsEmpty())
				{
					String localModName = dllName;
					const int dotIndex = localModName.ReverseFind('.');
					localModName.Remove(dotIndex, localModName.GetLength() - dotIndex);
					funcEntry.FunctionName = Format("%s.%i", localModName, funcEntry.Ordinal);
				}
				
				// Read function address from thunk data and increment function iteration counter.
				DWORD funcAddress;
				CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pDesc.FirstThunk + count++ * sizeof(DWORD)), &funcAddress, sizeof(DWORD), NULL);
	
				if (!funcAddress)
				{
					continue;
				}
				
				funcEntry.VirtualAddress = funcAddress;
				funcEntry.Flag = 0;
				
				// Check whether actual address is equal to the address it should be, otherwise the IAT is hooked.
				const SIZE_T eatAddress = this->GetAddressFromExportTable(&addrStruct, funcEntry.Ordinal ? (char*)funcEntry.Ordinal : funcEntry.FunctionName.Begin(), funcEntry.Ordinal);
				if (eatAddress == EAT_ADDRESS_NOT_FOUND)
				{
					funcEntry.Flag = IAT_FLAG_NOT_FOUND;
				}
				else if (eatAddress != funcEntry.VirtualAddress)
				{
					funcEntry.Flag = IAT_FLAG_HOOKED;
				}
				
				// Add function to import descriptor.
				impDesc.FunctionList.Add(funcEntry);
			}
			while (thunk.u1.AddressOfData);
			
			delete[] exportDirectoryBuffer;
        }

		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (++counter * sizeof(IMAGE_IMPORT_DESCRIPTOR))), &pDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);
	}
	
	// Success, free used buffers and return.
	delete[] moduleBuffer;
}

// Places a hook in the IAT, replacing the function address with another one.
// First parameter is either a pointer to a buffer containing the function name or an ordinal value.
bool PortableExecutable32::PlaceIATHook(const Win32ModuleInformation* modBase, const char* NameOrdinal, const SIZE_T newAddress, bool IsOrdinal) const
{
	bool result = false;
	Byte* const moduleBuffer = new Byte[modBase->Length];
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)this->mBaseAddress, moduleBuffer, modBase->Length, NULL);
	
	const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
	const IMAGE_OPTIONAL_HEADER32* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;
	
	const IMAGE_IMPORT_DESCRIPTOR* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)(moduleBuffer + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	// Additional sanity checking, to avoid pDesc to be located outside of the allocated buffer.
	if ((Byte*)pDesc > moduleBuffer && (Byte*)pDesc < moduleBuffer + modBase->Length)
	{
		while (pDesc->FirstThunk)
		{
			const char* dllName = (char*)(moduleBuffer + pDesc->Name);
			
			IMAGE_THUNK_DATA32* thunk;
	        unsigned int count = 0;
	
			do
			{
				thunk = (IMAGE_THUNK_DATA32*)(moduleBuffer + pDesc->OriginalFirstThunk + count * sizeof(DWORD));
				void* const AddressAddr = (void*)(this->mBaseAddress + pDesc->FirstThunk + count++ * sizeof(DWORD));
	
				if (IsOrdinal)
				{
					if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
					{
						// Ordinal import detected, check whether ordinal matches input value.
						if (IMAGE_ORDINAL32(thunk->u1.Ordinal) == (SIZE_T)NameOrdinal)
						{
							DWORD dwOldProtect;
							CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
							CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, AddressAddr, &newAddress, sizeof(DWORD), NULL);
							CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(DWORD), dwOldProtect, &dwOldProtect);
							result = true;
							break;
						}
					}
				}
				else
				{
					// Check if function is ordinal, because if it is, skip this one.
					if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
					{
						continue;
					}
					
					const char* funcName = (char*)(moduleBuffer + thunk->u1.AddressOfData + sizeof(WORD));
					
					// Named import detected, check whether import matches input name.
					if (strcmp(funcName, NameOrdinal) == 0)
					{
						DWORD dwOldProtect;
						CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
						CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, AddressAddr, &newAddress, sizeof(DWORD), NULL);
						CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(DWORD), dwOldProtect, &dwOldProtect);
						result = true;
						break;
					}
				}
			}
			while (thunk->u1.AddressOfData);
			
			++pDesc;
		}
	}
	
	// Success, free used buffers and return.
	delete[] moduleBuffer;
	return result;
}

// Attempts to restore the PE headers from a file on the harddisk to a module loaded in memory.
// Retuns true if the operation succeeded and false if it did not succeed.
bool PortableExecutable32::RestorePEHeaderFromFile(const String& fileName, const Win32ModuleInformation& module) const
{
	bool result = true;
	
	// Create handle to file on the disk.
	HANDLE hFile = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE)
	{
		result = false;
	}
	
	// Get file size and read file into buffer.
	LARGE_INTEGER size;
	GetFileSizeEx(hFile, &size);
	
	DWORD bytesRead;
	Byte* const fileBuffer = new Byte[size.LowPart];
	if (!ReadFile(hFile, fileBuffer, size.LowPart, &bytesRead, NULL))
	{
		result = false;
	}
	
	// Read header size.
	const IMAGE_DOS_HEADER* const pDOSHeader = (IMAGE_DOS_HEADER*)fileBuffer;
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}
	
	const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		result = false;
	}
	
	const IMAGE_OPTIONAL_HEADER32* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;

	// Write header data into process memory at designated location.
	CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, (void*)module.BaseAddress, pOptionalHeader->SizeOfHeaders, PAGE_READWRITE, &bytesRead);

	if (!CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, (void*)module.BaseAddress, fileBuffer, pOptionalHeader->SizeOfHeaders, NULL))
	{
		result = false;
	}

	CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, (void*)module.BaseAddress, pOptionalHeader->SizeOfHeaders, bytesRead, &bytesRead);
	
	delete[] fileBuffer;
	CloseHandle(hFile);
	
	return result;
}

// Attempts to hide a module from the loaded process. Hiding means it not being visible for debuggers anymore.
// Returns true if the operation succeeded, and false if it did not succeed.
bool PortableExecutable32::HideModuleFromProcess(const Win32ModuleInformation& module) const
{
	if (!CrySearchRoutines.NtQueryInformationProcess)
	{
		return false;
	}
	
	// Retrieve target process information using Nt function.
#ifdef _WIN64
	ULONG_PTR pebAddr;
	if (CrySearchRoutines.NtQueryInformationProcess(this->mProcessHandle, ProcessWow64Information, &pebAddr, sizeof(ULONG_PTR), NULL) != STATUS_SUCCESS)
#else
	PROCESS_BASIC_INFORMATION procBlock;
	if (CrySearchRoutines.NtQueryInformationProcess(this->mProcessHandle, ProcessBasicInformation, &procBlock, sizeof(PROCESS_BASIC_INFORMATION), NULL) != STATUS_SUCCESS)
#endif
	{
		return false;
	}
	
	PEB_LDR_DATA32 peb;
	SIZE_T pebPtr;

	// Read process environment block and loader data from the process memory.
#ifdef _WIN64
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (unsigned char*)pebAddr + offsetof(PEB32, LoaderData), &pebPtr, sizeof(DWORD), NULL);
#else
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (unsigned char*)procBlock.PebBaseAddress + offsetof(PEB, LoaderData), &pebPtr, sizeof(DWORD), NULL);
#endif
	CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)pebPtr, &peb, sizeof(PEB_LDR_DATA), NULL);

	LDR_MODULE32 curModule;
	bool found = false;
	unsigned int retryCount = 0;
	int moduleCount = 0;

    SIZE_T Head = peb.InMemoryOrderModuleList.Flink;
    SIZE_T Node = Head;

    do
    {
		// Read current linked list module from the process memory.
        if (CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(Node -= sizeof(LIST_ENTRY32)), &curModule, sizeof(LDR_MODULE32), NULL))
        {
            if (curModule.BaseAddress)
            {
				// some applications cause an infinite loop. This is one way to help preventing it.
				++moduleCount;

				// A valid module is found, read its base dll name from the process memory.
                wchar BaseDllName[MAX_PATH];
                CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)curModule.BaseDllName.Buffer, BaseDllName, curModule.BaseDllName.Length, NULL);
                BaseDllName[curModule.BaseDllName.Length / 2] = 0;
                PathStripPathW(BaseDllName);
                
                // Compare current module's base name and desired module name, if it matches, the desired one is found.
                String selModName = mModuleManager->GetModuleFilename(module.BaseAddress);
                if (memcmp(selModName.ToWString().Begin(), BaseDllName, selModName.GetLength() * sizeof(wchar)) == 0)
                {
                    found = true;
                    
                    for (unsigned int index = 0; index < 3; (Node += sizeof(LIST_ENTRY32)), index++)
                    {
				        LIST_ENTRY32 current;
						BOOL localRes = TRUE;

				        // Read current, previous and next list entry from the process memory.
						CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)Node, &current, sizeof(LIST_ENTRY32), NULL);
				        
						if (!localRes)
				        {
							found = false;
							break;
				        }
				        
						const SIZE_T nextItemAddr = current.Flink;
						const SIZE_T prevItemAddr = current.Blink;
						
						// Overwrite the pointers of the previous and next list entry so the current one is effectively hidden.
						localRes = CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, (void*)current.Blink, &nextItemAddr, sizeof(DWORD), NULL);
						localRes = CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, (unsigned char*)current.Flink + sizeof(DWORD), &prevItemAddr, sizeof(DWORD), NULL);
                    }
				    
                    break;
                }
            }
        }
		else
		{
			// Prevent infinite while looping. In most situations this code may be unnessecary.
			if (++retryCount == 3)
			{
				break;
			}
		}
		
		// Desired module was not yet found, traverse to the next one.
        Node = curModule.InMemoryOrderModuleList.Flink;
    }
    while(Head != Node && moduleCount < mModuleManager->GetModuleCount());

	return found;
}

// Dumps a specific section in the loaded process to a file on the harddisk.
// Returns true if the operation succeeded, and false if it did not succeed.
bool PortableExecutable32::DumpProcessSection(const String& fileName, const SIZE_T address, const SIZE_T size) const
{
	bool result = true;
	Byte* const buffer = new Byte[size];
	
	// Read section memory from target process and save it into the buffer.
	if (!CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + address), buffer, size, NULL))
	{
		result = false;
	}
	
	// Create dmp file on the disk.
	HANDLE hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		result = false;
	}
	
	// Write the data read to the file.
	DWORD bytesWritten;
#ifdef _WIN64
	if (!WriteFile(hFile, buffer, (DWORD)size, &bytesWritten, NULL))
#else
	if (!WriteFile(hFile, buffer, size, &bytesWritten, NULL))
#endif
	{
		DeleteFile(fileName);
		result = false;
	}
	
	// All succeeded, free resources and return.
	CloseHandle(hFile);
	delete[] buffer;
	return result;
}

// Attempts to load a dynamic link library into the target process.
// Returns true if the operation succeeded, and false if it did not succeed.
bool PortableExecutable32::LoadLibraryExternal(const String& library) const
{
	// Allocate memory space for the library path.
	void* const lpRemoteAddress = VirtualAllocEx(this->mProcessHandle, NULL, library.GetLength(), MEM_COMMIT, PAGE_READWRITE);
	SIZE_T bytesWritten;
	
	// Write path to library into the newly allocated memory.
	CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, lpRemoteAddress, library, library.GetLength(), &bytesWritten);
	if (bytesWritten != library.GetLength())
	{
		VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
		return false;
	}
	
	// Create a thread remotely that executes LoadLibraryA, pointing to the allocated string as parameter.
#ifndef _WIN64
	HANDLE hThread = CreateRemoteThread(this->mProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), lpRemoteAddress, NULL, NULL);
#else
	DWORD krnl32Base;
	const int modCount = mModuleManager->GetModuleCount();
	for (int i = 0; i < modCount; ++i)
	{
		if (ToLower(mModuleManager->GetModuleFilename((*mModuleManager)[i].BaseAddress)) == "kernel32.dll")
		{
			krnl32Base = (DWORD)(*mModuleManager)[i].BaseAddress;
			break;
		}
	}
	
	HANDLE hThread = CreateRemoteThread(this->mProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)Wow64GetProcAddress(this->mProcessHandle, krnl32Base, "LoadLibraryA"), lpRemoteAddress, NULL, NULL);
#endif
	
	// Succesfully created thread, wait for it to complete and free resources after.
	if (hThread && hThread != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(hThread, 5000);
		CloseHandle(hThread);
	}
	
	VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
	
	return !!hThread;
}

// Attempts to load a dynamic link library into the target process.
// Returns true if the operation succeeded, and false if it did not succeed.
bool PortableExecutable32::LoadLibraryExternalHijack(const String& library, HANDLE hThread) const
{
	// If the thread wasn't opened succesfully, the function can return inmediately.
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return false;
	}
		
	// Allocate memory space for the library path.
	void* const lpRemoteAddress = VirtualAllocEx(this->mProcessHandle, NULL, library.GetLength(), MEM_COMMIT, PAGE_READWRITE);
	SIZE_T bytesWritten;

	// Write path to library into the newly allocated memory.
	CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, lpRemoteAddress, library, library.GetLength(), &bytesWritten);
	if (bytesWritten != library.GetLength())
	{
		VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
		return false;
	}
	
	// The shellcode that is written and executed inside the target program:
	// push 0xCCCCCCCC
	// pushad
	// pushfd
	// mov ebx, 0xCCCCCCCC
	// push 0xCCCCCCCC
	// call ebx
	// popfd
	// popad
	// mov dword ptr [0xCCCCCCCC], 0x1337
	// ret
	Byte shellCode[] = { 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x60, 0x9C, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD3, 0x9D, 0x61, 0xC7, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x37, 0x13, 0x00, 0x00, 0xC3 };
	
	// Allocate executable block of memory for the shellcode.
	void* const lpShellCode = VirtualAllocEx(this->mProcessHandle, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	const SIZE_T flagAddress = (SIZE_T)lpShellCode + 0x100;
	
	// Suspend the thread and back up the context.
#ifdef _WIN64
	Wow64SuspendThread(hThread);
	WOW64_CONTEXT ctx;
	ctx.ContextFlags = WOW64_CONTEXT_FULL;
	Wow64GetThreadContext(hThread, &ctx);
#else
	SuspendThread(hThread);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
#endif
	
	// Replace addresses with correct ones at runtime.
	*(DWORD*)&shellCode[1] = ctx.Eip;
#ifdef _WIN64
	const Win32ModuleInformation* krnl32mod = mModuleManager->FindModule("kernel32.dll");
	if (!krnl32mod)
	{
		VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
		CloseHandle(hThread);
		return false;
	}
	
	*(DWORD*)&shellCode[8] = Wow64GetProcAddress(this->mProcessHandle, (DWORD)krnl32mod->BaseAddress, "LoadLibraryA");
#else
	*(DWORD*)&shellCode[8] = (DWORD)LoadLibraryA;
#endif
	*(DWORD*)&shellCode[13] = (DWORD)lpRemoteAddress;
	*(DWORD*)&shellCode[23] = flagAddress;
	
	// Write the shellcode to the remotely allocated buffer.
	CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, lpShellCode, shellCode, sizeof(shellCode), &bytesWritten);
	if (bytesWritten != sizeof(shellCode))
	{
		VirtualFreeEx(this->mProcessHandle, lpShellCode, 0, MEM_RELEASE);
		VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
		return false;
	}
	
	// Change EIP to resume execution at the shellcode.
	ctx.Eip = (DWORD)lpShellCode;
	
	// Place the new context inside the thread.
#ifdef _WIN64
	Wow64SetThreadContext(hThread, &ctx);
#else
	SetThreadContext(hThread, &ctx);
#endif
	
	// Flush the instruction cache to avoid problems with cached instructions.
	FlushInstructionCache(this->mProcessHandle, lpShellCode, sizeof(shellCode));
	
	// Resume the thread to let the DLL load and close thread handle.
	ResumeThread(hThread);
	
	// Sample the completion flag to contain the magic number 0x1337. Block the thread until the sampling is succesful.
	DWORD magic = 0;
	do
	{
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)flagAddress, &magic, sizeof(DWORD), &bytesWritten);
		
		// Prevent CrySearch to start eating CPU time while still trying to have an accurate sample.
		Sleep(75);
	}
	while (magic != 0x1337);
	
	// The loop finished, free memory pages and close thread handle.
	VirtualFreeEx(this->mProcessHandle, lpShellCode, 0, MEM_RELEASE);
	VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
	CloseHandle(hThread);
	
	return !!hThread;
}

// Attempts to unload a loaded module from the target process.
void PortableExecutable32::UnloadLibraryExternal(const SIZE_T module) const
{
#ifndef _WIN64
	HANDLE hThread = CreateRemoteThread(this->mProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary"), (void*)module, NULL, NULL);
#else
	DWORD krnl32Base;
	const int modCount = mModuleManager->GetModuleCount();
	for (int i = 0; i < modCount; ++i)
	{
		if (ToLower(mModuleManager->GetModuleFilename((*mModuleManager)[i].BaseAddress)) == "kernel32.dll")
		{
			krnl32Base = (DWORD)(*mModuleManager)[i].BaseAddress;
			break;
		}
	}

	DWORD freeAddr = Wow64GetProcAddress(this->mProcessHandle, krnl32Base, "FreeLibrary");
	HANDLE hThread = CreateRemoteThread(this->mProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)freeAddr, (void*)module, NULL, NULL);
#endif
	
	// Succesfully created thread, wait for it to complete and free resources after.
	if (hThread && hThread != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(hThread, 5000);
		CloseHandle(hThread);
	}
}

// Restores the original address of an imported function from the export table.
void PortableExecutable32::RestoreExportTableAddressImport(const Win32ModuleInformation* modBase, const SIZE_T baseAddress, const char* NameOrdinal, bool IsOrdinal) const
{
	Byte* const dllBuffer = new Byte[0x400];
    CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)baseAddress, dllBuffer, 0x400, NULL);
   
    const IMAGE_NT_HEADERS32* const pNTHeader =(IMAGE_NT_HEADERS32*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
	IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

    delete[] dllBuffer;
    
    Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
    CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(baseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
    
	Byte* const bufBase = (exportDirectoryBuffer - dataDir.VirtualAddress);
	AddrStruct addrStruct((Byte*)baseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
		, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);
    
	this->PlaceIATHook(modBase, NameOrdinal, this->GetAddressFromExportTable(&addrStruct, NameOrdinal, IsOrdinal), IsOrdinal);
	
	delete[] exportDirectoryBuffer;
}

// -------------------------------------------------------------------------------------------------------------------------------
// PE 64 methods
// -------------------------------------------------------------------------------------------------------------------------------

#ifdef _WIN64
	PortableExecutable64::~PortableExecutable64()
	{
		
	}
	
	// Retrieves PE header information from the loaded process. Information is saved in global storage that has process lifetime.
	// Note that IMAGE_NT_HEADERS and IMAGE_OPTIONAL_HEADER are explicitly defined as the 32 bit version. If compiled as 64 bit the structs differ.
	void PortableExecutable64::GetExecutablePeInformation() const
	{
		// Clear image sections before getting new ones.
		LoadedProcessPEInformation.Reset();
	
		// Read process memory into local buffer in order to load PE headers.
		Byte* moduleBuffer = new Byte[0x400];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)this->mBaseAddress, moduleBuffer, 0x400, NULL);
		
		// Load PE headers.
		const IMAGE_NT_HEADERS64* const pNTHeader =(IMAGE_NT_HEADERS64*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
		
		// When the PE Headers are destroyed at runtime the pointer to the headers may run out of the buffer's bounds.
		if ((Byte*)pNTHeader > (moduleBuffer + 0x400))
		{
			delete[] moduleBuffer;
			LoadedProcessPEInformation.PEFields.Clear();
			return;
		}
		
		const IMAGE_OPTIONAL_HEADER64* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader;
		const IMAGE_FILE_HEADER* const pFileHeader = &(pNTHeader->FileHeader);
		
		// Retrieve the type of machine the PE executable can run on.
		this->ParseMachineType(pFileHeader->Machine);
		
		// Retrieve PE fields and add them to the map.
		LoadedProcessPEInformation.PEFields.Add("Number of sections", pFileHeader->NumberOfSections);
		LoadedProcessPEInformation.PEFields.Add("Size of optional header", Format("%X", pFileHeader->SizeOfOptionalHeader));
		LoadedProcessPEInformation.PEFields.Add("Pointer to symbol table", (int)pFileHeader->PointerToSymbolTable);
		LoadedProcessPEInformation.PEFields.Add("Number of symbols", (int)pFileHeader->NumberOfSymbols);
		LoadedProcessPEInformation.PEFields.Add("Image base", Format("%llX", (__int64)pOptionalHeader->ImageBase));
		LoadedProcessPEInformation.PEFields.Add("Base of code", Format("%llX", (__int64)pOptionalHeader->BaseOfCode));
		LoadedProcessPEInformation.PEFields.Add("Address of entrypoint", Format("%llX", (__int64)pOptionalHeader->AddressOfEntryPoint));
		LoadedProcessPEInformation.PEFields.Add("Size of code", Format("%llX", (__int64)pOptionalHeader->SizeOfCode));
		LoadedProcessPEInformation.PEFields.Add("Size of initialized data", Format("%llX", (__int64)pOptionalHeader->SizeOfInitializedData));
		LoadedProcessPEInformation.PEFields.Add("Size of uninitialized data", Format("%llX", (__int64)pOptionalHeader->SizeOfUninitializedData));
		LoadedProcessPEInformation.PEFields.Add("Section alignment", Format("%llX", (__int64)pOptionalHeader->SectionAlignment));
		LoadedProcessPEInformation.PEFields.Add("File alignment", Format("%llX", (__int64)pOptionalHeader->FileAlignment));
		LoadedProcessPEInformation.PEFields.Add("Size of image", Format("%llX", (__int64)pOptionalHeader->SizeOfImage));
		LoadedProcessPEInformation.PEFields.Add("Size of headers", Format("%llX", (__int64)pOptionalHeader->SizeOfHeaders));
		LoadedProcessPEInformation.PEFields.Add("Checksum", Format("%llX", (__int64)pOptionalHeader->CheckSum));
		LoadedProcessPEInformation.PEFields.Add("Linker version", Format("%i.%i", pOptionalHeader->MajorLinkerVersion, pOptionalHeader->MinorLinkerVersion));
		LoadedProcessPEInformation.PEFields.Add("OS version", Format("%i.%i", pOptionalHeader->MajorOperatingSystemVersion, pOptionalHeader->MinorOperatingSystemVersion));
		LoadedProcessPEInformation.PEFields.Add("Image version", Format("%i.%i", pOptionalHeader->MajorImageVersion, pOptionalHeader->MinorImageVersion));
		LoadedProcessPEInformation.PEFields.Add("Subsystem version", Format("%i.%i", pOptionalHeader->MajorSubsystemVersion, pOptionalHeader->MinorSubsystemVersion));
		LoadedProcessPEInformation.PEFields.Add("Number of data directories", Format("%llX", (__int64)pOptionalHeader->NumberOfRvaAndSizes));
		
		// Parse the last general property value of the PE header, save the section values and destroy the buffer.
		this->ParseSubsystemValue(pOptionalHeader->Subsystem);
		const DWORD sectionCount = pNTHeader->FileHeader.NumberOfSections;
		const DWORD sectionSizeBytes = sizeof(IMAGE_SECTION_HEADER) * sectionCount;
		const IMAGE_SECTION_HEADER* const firstSectionPtr = (IMAGE_SECTION_HEADER*)(this->mBaseAddress + ((Byte*)IMAGE_FIRST_SECTION(pNTHeader) - moduleBuffer));
		
		// Get the COM header from the PE file.
		this->GetDotNetDirectoryInformation(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]);
	
		delete[] moduleBuffer;
	
		moduleBuffer = new Byte[sectionSizeBytes];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, firstSectionPtr, moduleBuffer, sectionSizeBytes, NULL);
		this->GetImageSectionsList((IMAGE_SECTION_HEADER*)moduleBuffer, sectionCount, LoadedProcessPEInformation.ImageSections);
		delete[] moduleBuffer;
	}
	
	// Retrieves the address of a function in the export table of a module. Address can be returned for function by name or ordinal.
	// Returns the address of the function, created from the module base address added by the function RVA.
	// If the function is not found, the return value is 0xFFFFFFFF.
	SIZE_T PortableExecutable64::GetAddressFromExportTable(const AddrStruct* addr, const char* NameOrdinal, bool IsOrdinal) const
	{
		if (addr->ExportDirectory->AddressOfNameOrdinals)
		{
			const DWORD* funcAddrPtr = NULL;
			int RecurseDotIndex = 0;
			
			for (unsigned int i = 0; i < addr->ExportDirectory->NumberOfFunctions; ++i)
			{
				const WORD* const ordValue = (WORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNameOrdinals + (i * sizeof(WORD)));
	
				if (IsOrdinal)
				{
					bool found = false;
					
					// Compare ordinal values without magic bitoperations!
					if ((addr->ExportDirectory->Base + *ordValue) == *reinterpret_cast<WORD*>(&NameOrdinal))
					{
						funcAddrPtr = (DWORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfFunctions + (sizeof(DWORD) * *ordValue));
						found = true;
					}
					
					// Skip the entry if it is not found.
					if (!found || ((Byte*)funcAddrPtr < addr->BufferBaseAddress || (Byte*)funcAddrPtr > addr->BufferEndAddress))
					{
						continue;
					}

					if (*funcAddrPtr > addr->DirectoryAddress->VirtualAddress && *funcAddrPtr < addr->DirectoryAddress->VirtualAddress + addr->DirectoryAddress->Size)
					{
						const Win32ModuleInformation* modBaseAddr = this->GetResolvedModule(addr->BufferBaseAddress, &RecurseDotIndex, funcAddrPtr, NameOrdinal);
						if (!modBaseAddr || (SIZE_T)addr->BaseAddress == modBaseAddr->BaseAddress)
						{
							return EAT_ADDRESS_NOT_FOUND;
						}
	
						Byte* const dllBuffer = new Byte[0x400];
				        CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)modBaseAddr->BaseAddress, dllBuffer, 0x400, NULL);
				           
				        const IMAGE_NT_HEADERS64* pNTHeader =(IMAGE_NT_HEADERS64*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
						IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
				
				        delete[] dllBuffer;
				            
				        Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
				        CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(modBaseAddr->BaseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
						
						Byte* const bufBase = exportDirectoryBuffer - dataDir.VirtualAddress;
						AddrStruct addrStruct((Byte*)modBaseAddr->BaseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
							, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);

						SIZE_T forwardedAddress = this->GetAddressFromExportTable(&addrStruct, (char*)ScanInt((char*)(addr->BufferBaseAddress + *funcAddrPtr + RecurseDotIndex + 1), NULL, 10), true);
						delete[] exportDirectoryBuffer;
						return forwardedAddress;
					}
	
					return (SIZE_T)(addr->BaseAddress + *funcAddrPtr);
				}
				else
				{
					const DWORD* const stringPtr = (DWORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNames + (i * sizeof(DWORD)));
					const char* const functionName = (char*)(addr->BufferBaseAddress + *stringPtr);
				
					const size_t strlength = strlen(NameOrdinal);
					if ((functionName > (char*)addr->BufferBaseAddress + addr->DirectoryAddress->VirtualAddress && (functionName + strlength + 1) < (char*)addr->BufferEndAddress) && memcmp(NameOrdinal, functionName, strlength) == 0)
					{
						funcAddrPtr = (DWORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfFunctions + (sizeof(DWORD) * *ordValue));
						if (*funcAddrPtr > addr->DirectoryAddress->VirtualAddress && *funcAddrPtr < addr->DirectoryAddress->VirtualAddress + addr->DirectoryAddress->Size)
						{
							const Win32ModuleInformation* modBaseAddr = this->GetResolvedModule(addr->BufferBaseAddress, &RecurseDotIndex, funcAddrPtr, NameOrdinal);
							if (!modBaseAddr || (SIZE_T)addr->BaseAddress == modBaseAddr->BaseAddress)
							{
								return EAT_ADDRESS_NOT_FOUND;
							}

							Byte* const dllBuffer = new Byte[0x400];
				            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)modBaseAddr->BaseAddress, dllBuffer, 0x400, NULL);
				           
				            const IMAGE_NT_HEADERS64* const pNTHeader =(IMAGE_NT_HEADERS64*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
							IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
				
				            delete[] dllBuffer;
				            
				            Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
				            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(modBaseAddr->BaseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
							
							Byte* const bufBase = exportDirectoryBuffer - dataDir.VirtualAddress;
							AddrStruct addrStruct((Byte*)modBaseAddr->BaseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
								, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);
				            
							SIZE_T forwardedAddress = this->GetAddressFromExportTable(&addrStruct, (char*)(addr->BufferBaseAddress + *funcAddrPtr + RecurseDotIndex + 1), false);
							delete[] exportDirectoryBuffer;
							return forwardedAddress;
						}
	
						return (SIZE_T)(addr->BaseAddress + *funcAddrPtr);
					}
				}
			}
		}
		
		return EAT_ADDRESS_NOT_FOUND;
	}
	
	// Attempts to retrieve function name associated to ordinal import from the export table of the loaded module.
	// Returns a pointer to the function name if it exists. If the function is not found, the return value is NULL.
	const char* PortableExecutable64::GetOrdinalFunctionNameFromExportTable(const AddrStruct* addr, const WORD ordinal) const
	{
		const WORD* const ordinals = (WORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNameOrdinals);
		
		for (unsigned int i = 0; i < addr->ExportDirectory->NumberOfFunctions; ++i)
		{
			if ((addr->ExportDirectory->Base + ordinals[i]) == ordinal)
			{
				const DWORD* const stringPtr = (DWORD*)(addr->BufferBaseAddress + addr->ExportDirectory->AddressOfNames + i * sizeof(DWORD));
				const Byte* const absStringPtr = (Byte*)(addr->BufferBaseAddress + *stringPtr);
				
				// Make sure the string points inside of the buffer. Scrambled EAT would crash the application.
				if (absStringPtr > (addr->BufferBaseAddress + addr->DirectoryAddress->Size) && absStringPtr < addr->BufferEndAddress)
				{
					return (const char*)absStringPtr;
				}
			}
		}
		
		return NULL;
	}

	
	// Retrieves the import table from the PE header of the loaded process. This information is stored in the global storage that has process lifetime.
	void PortableExecutable64::GetImportAddressTable() const
	{
		// Read process memory into local buffer in order to load IAT.
		Byte* const moduleBuffer = new Byte[0x400];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)this->mBaseAddress, moduleBuffer, 0x400, NULL);
		
		const IMAGE_NT_HEADERS64* const pNTHeader = (IMAGE_NT_HEADERS*)((BYTE*)moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
		
		// The PE Headers are not valid, the pointer runs outside the bounds of the buffer.
		if ((Byte*)pNTHeader > (moduleBuffer + 0x400))
		{
			delete[] moduleBuffer;
			return;
		}
		
		const IMAGE_OPTIONAL_HEADER* const pOptionalHeader = ((IMAGE_OPTIONAL_HEADER*)&pNTHeader->OptionalHeader);
		
		unsigned int counter = 0;
		IMAGE_IMPORT_DESCRIPTOR pDesc;
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (counter * sizeof(IMAGE_IMPORT_DESCRIPTOR))), &pDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);
		
		while (pDesc.FirstThunk && pDesc.Name != 0xFFFF)
		{
			// Read DLL name from import descriptor entry.
			char dllName[48];
			CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(pDesc.Name + this->mBaseAddress), dllName, 48, NULL);
	        
	        // Add new import descriptor to the table.
	        ImportTableDescriptor& impDesc = LoadedProcessPEInformation.ImportAddressTable.Add();
	        impDesc.ModuleName = dllName;
	        
	        // Get base address and length of desired DLL, and look up the function foreign name in the export table of that DLL.
			const Win32ModuleInformation* modBaseAddr = NULL;
			if (ToLower(dllName).StartsWith("api-ms-win"))
			{
				// Windows 6.x ApiSetSchema redirection detected, resolve the redirection.
				WString unicodeBuffer(dllName);
				unicodeBuffer.Remove(0, 4);
				unicodeBuffer.Remove(unicodeBuffer.GetLength() - 4, 4);
				
				const wchar* const outWString = this->InlineResolveApiSetSchema(unicodeBuffer);
				if (outWString)
				{
					WString redirectedDll = outWString;
					delete[] outWString;
				
					modBaseAddr = mModuleManager->FindModule(redirectedDll.ToString());
					impDesc.LogicalBaseAddress = modBaseAddr ? modBaseAddr->BaseAddress : 0;
				}
			}
			else
			{
				modBaseAddr = mModuleManager->FindModule(dllName);
				impDesc.LogicalBaseAddress = 0;
			}
	        
			if (modBaseAddr)
			{
	            Byte* const dllBuffer = new Byte[0x400];
	            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)modBaseAddr->BaseAddress, dllBuffer, 0x400, NULL);
	           
	            const IMAGE_NT_HEADERS64* pNTHeader =(IMAGE_NT_HEADERS64*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
				IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	            
	            delete[] dllBuffer;
	            
	            Byte* exportDirectoryBuffer = new Byte[dataDir.Size];
	            CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(modBaseAddr->BaseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
	            
				Byte* const bufBase = exportDirectoryBuffer - dataDir.VirtualAddress;
				AddrStruct addrStruct((Byte*)modBaseAddr->BaseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
					, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);
	        
				IMAGE_THUNK_DATA thunk;
		        unsigned int count = 0;
	        
				do
				{
					CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pDesc.OriginalFirstThunk + count * sizeof(IMAGE_THUNK_DATA)), &thunk, sizeof(IMAGE_THUNK_DATA), NULL);
				
					ImportAddressTableEntry funcEntry;
					
					// Check for 64-bit ordinal magic flag.
					if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64)
					{
						funcEntry.Ordinal = IMAGE_ORDINAL64(thunk.u1.Ordinal);
						funcEntry.Hint = 0;
						
						if (addrStruct.ExportDirectory->AddressOfNames)
						{
							funcEntry.FunctionName = this->GetOrdinalFunctionNameFromExportTable(&addrStruct, funcEntry.Ordinal);
						}
					}
					else
					{
						char funcName[96];
						CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + thunk.u1.AddressOfData), funcName, 96, NULL);
					
						// Set ordinal value to 0, read function name and WORD sized hint from the first two read bytes sequence.
						funcEntry.Ordinal = 0;
						funcEntry.Hint = *(WORD*)funcName;
						funcEntry.FunctionName = funcName + sizeof(WORD);
					}
					
					// In a rare occasion the ordinal bit-flag is already removed. In this case the ordinal should be detected by section awareness.
					if (funcEntry.FunctionName.IsEmpty() && !RVAPointsInsideSection((DWORD)thunk.u1.Ordinal))
					{
						funcEntry.Ordinal = (WORD)thunk.u1.Ordinal;
						funcEntry.Hint = 0;
						
						if (addrStruct.ExportDirectory->AddressOfNames)
						{
							funcEntry.FunctionName = this->GetOrdinalFunctionNameFromExportTable(&addrStruct, funcEntry.Ordinal);
						}
					}
					
					// If the function name is empty even after ordinal resolving, the function has no name. Give it an automated name.
					if (funcEntry.FunctionName.IsEmpty())
					{
						String localModName = dllName;
						const int dotIndex = localModName.ReverseFind('.');
						localModName.Remove(dotIndex, localModName.GetLength() - dotIndex);
						funcEntry.FunctionName = Format("%s.%i", localModName, funcEntry.Ordinal);
					}
					
					// Read function address from thunk data and increment function iteration counter.
					SIZE_T funcAddress;
					CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pDesc.FirstThunk + count++ * sizeof(SIZE_T)), &funcAddress, sizeof(SIZE_T), NULL);
	
					if (!funcAddress)
					{
						continue;
					}
				
					funcEntry.VirtualAddress = funcAddress;
					funcEntry.Flag = 0;
					
					// Check whether actual address is equal to the address it should be, otherwise the IAT is hooked.
					const SIZE_T eatAddress = this->GetAddressFromExportTable(&addrStruct, funcEntry.Ordinal ? (char*)funcEntry.Ordinal : funcEntry.FunctionName.Begin(), funcEntry.Ordinal);
					if (eatAddress == EAT_ADDRESS_NOT_FOUND)
					{
						funcEntry.Flag = IAT_FLAG_NOT_FOUND;
					}
					else if (eatAddress != funcEntry.VirtualAddress)
					{
						funcEntry.Flag = IAT_FLAG_HOOKED;
					}
			
					// Add function to import descriptor.
					impDesc.FunctionList.Add(funcEntry);
				}
				while (thunk.u1.AddressOfData);
			
				delete[] exportDirectoryBuffer;
			}
			
			CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (++counter * sizeof(IMAGE_IMPORT_DESCRIPTOR))), &pDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);
		}
		
		// Success, free used buffers and return.
		delete[] moduleBuffer;
	}
	
	// Places a hook in the IAT, replacing the function address with another one.
	// First parameter is either a pointer to a buffer containing the function name or an ordinal value.
	bool PortableExecutable64::PlaceIATHook(const Win32ModuleInformation* modBase, const char* NameOrdinal, const SIZE_T newAddress, bool IsOrdinal) const
	{
		bool result = false;
		Byte* const moduleBuffer = new Byte[modBase->Length];
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)this->mBaseAddress, moduleBuffer, modBase->Length, NULL);
		
		const IMAGE_NT_HEADERS* const pNTHeader =(IMAGE_NT_HEADERS*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
		const IMAGE_IMPORT_DESCRIPTOR* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)(moduleBuffer + ((IMAGE_OPTIONAL_HEADER*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		
		// Additional sanity checking, to avoid pDesc to be located outside of the allocated buffer.
		if ((Byte*)pDesc > moduleBuffer && (Byte*)pDesc < moduleBuffer + modBase->Length)
		{
			while (pDesc->FirstThunk)
			{
				// Read DLL name from import descriptor entry.
				const char* const dllName = (char*)(moduleBuffer + pDesc->Name);
		
				IMAGE_THUNK_DATA* thunk;
		        unsigned int count = 0;
		        
				do
				{
					IMAGE_THUNK_DATA* const curAddress = (IMAGE_THUNK_DATA*)(moduleBuffer + pDesc->OriginalFirstThunk + count * sizeof(IMAGE_THUNK_DATA));
					
					// Read current thunk into local memory.
					thunk = curAddress;
					void* const AddressAddr = (void*)(this->mBaseAddress + pDesc->FirstThunk + count++ * sizeof(IMAGE_THUNK_DATA));
					
					if (IsOrdinal)
					{
						if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						{
							// Ordinal import detected, check whether ordinal matches input value.
							if (IMAGE_ORDINAL64(thunk->u1.Ordinal) == (SIZE_T)NameOrdinal)
							{
								DWORD dwOldProtect;
								CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &dwOldProtect);
								CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, AddressAddr, &newAddress, sizeof(IMAGE_THUNK_DATA), NULL);
								CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(IMAGE_THUNK_DATA), dwOldProtect, &dwOldProtect);
								result = true;
								break;
							}
						}
					}
					else
					{
						// If the current import is not a named one, move over to the next.
						if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						{
							continue;
						}
	
						// Read function name from thunk data.
						const char* const funcName = (char*)(moduleBuffer + thunk->u1.AddressOfData + sizeof(WORD));
						
						// Named import detected, check whether import matches input name.
						if (strcmp(funcName, NameOrdinal) == 0)
						{
							DWORD dwOldProtect;
							CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &dwOldProtect);
							CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, AddressAddr, &newAddress, sizeof(IMAGE_THUNK_DATA), NULL);
							CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, AddressAddr, sizeof(IMAGE_THUNK_DATA), dwOldProtect, &dwOldProtect);
							result = true;
							break;
						}
					}
				}
				while (thunk->u1.AddressOfData);
				
				++pDesc;
			}
		}
		
		// Success, free used buffers and return.
		delete[] moduleBuffer;
		return result;
	}
	
	// Attempts to restore the PE headers from a file on the harddisk to a module loaded in memory.
	// Retuns true if the operation succeeded and false if it did not succeed.
	bool PortableExecutable64::RestorePEHeaderFromFile(const String& fileName, const Win32ModuleInformation& module) const
	{
		bool result = true;
		
		// Create handle to file on the disk.
		HANDLE hFile = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			result = false;
		}
		
		// Get file size and read file into buffer.
		LARGE_INTEGER size;
		GetFileSizeEx(hFile, &size);
		
		DWORD bytesRead;
		Byte* const fileBuffer = new Byte[size.LowPart];
		if (!ReadFile(hFile, fileBuffer, size.LowPart, &bytesRead, NULL))
		{
			result = false;
		}
		
		// Read header size.
		const IMAGE_DOS_HEADER* const pDOSHeader = (IMAGE_DOS_HEADER*)fileBuffer;
		if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}
	
		const IMAGE_NT_HEADERS* const pNTHeader =(IMAGE_NT_HEADERS*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			result = false;
		}
		
		const IMAGE_OPTIONAL_HEADER* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER*)&pNTHeader->OptionalHeader;

		// Write header data into process memory at designated location.
		CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, (void*)module.BaseAddress, pOptionalHeader->SizeOfHeaders, PAGE_READWRITE, &bytesRead);
	
		if (!CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, (void*)module.BaseAddress, fileBuffer, pOptionalHeader->SizeOfHeaders, NULL))
		{
			result = false;
		}
	
		CrySearchRoutines.CryProtectMemoryRoutine(this->mProcessHandle, (void*)module.BaseAddress, pOptionalHeader->SizeOfHeaders, bytesRead, &bytesRead);
		
		delete[] fileBuffer;
		CloseHandle(hFile);
		
		return result;
	}
	
	// Attempts to hide a module from the loaded process. Hiding means it not being visible for debuggers anymore.
	// Returns true if the operation succeeded, and false if it did not succeed.
	bool PortableExecutable64::HideModuleFromProcess(const Win32ModuleInformation& module) const
	{
		if (!CrySearchRoutines.NtQueryInformationProcess)
		{
			return false;
		}
		
		// Retrieve target process information using Nt function.
		PROCESS_BASIC_INFORMATION procBlock;
		if (CrySearchRoutines.NtQueryInformationProcess(this->mProcessHandle, ProcessBasicInformation, &procBlock, sizeof(procBlock), NULL) != STATUS_SUCCESS)
		{
			return false;
		}
		
		PEB_LDR_DATA peb;
		PPEB_LDR_DATA pebPtr;
	
		// Read process environment block and loader data from the process memory.
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (unsigned char*)procBlock.PebBaseAddress + offsetof(PEB, LoaderData), &pebPtr, sizeof(PPEB_LDR_DATA), NULL);
		CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, pebPtr, &peb, sizeof(PEB_LDR_DATA), NULL);
	
		LDR_MODULE curModule;
		bool found = false;
		int retryCount = 0;
		int moduleCount = 0;
	
	    LIST_ENTRY* Head = peb.InMemoryOrderModuleList.Flink;
	    LIST_ENTRY* Node = Head;
	
	    do
	    {
			// Read current linked list module from the process memory.
	        if (CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, --Node, &curModule, sizeof(LDR_MODULE), NULL))
	        {
	            if (curModule.BaseAddress)
	            {
					// some applications cause an infinite loop. This is one way to help preventing it.
					++moduleCount;
	
					// A valid module is found, read its base dll name from the process memory.
	                wchar BaseDllName[MAX_PATH];
	                CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, curModule.BaseDllName.Buffer, BaseDllName, curModule.BaseDllName.Length, NULL);
	                BaseDllName[curModule.BaseDllName.Length / 2] = 0;
	                PathStripPathW(BaseDllName);
	                
	                // Compare current module's base name and desired module name, if it matches, the desired one is found.
	                String selModName = mModuleManager->GetModuleFilename(module.BaseAddress);
	                if (memcmp(selModName.ToWString().Begin(), BaseDllName, selModName.GetLength() * sizeof(wchar)) == 0)
	                {
	                    found = true;
	                    
	                    for (unsigned int index = 0; index < 3; Node++, index++)
	                    {
					        LIST_ENTRY current;
					        BOOL localRes = TRUE;
					        
					        // Read current, previous and next list entry from the process memory.
							CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, Node, &current, sizeof(LIST_ENTRY), NULL);
					        
					        if (!localRes)
					        {
								found = false;
								break;
					        }
					        
							const unsigned __int64 nextItemAddr = (unsigned __int64)current.Flink;
							const unsigned __int64 prevItemAddr = (unsigned __int64)current.Blink;
							
							// Overwrite the pointers of the previous and next list entry so the current one is effectively hidden.
					        localRes = CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, current.Blink, &nextItemAddr, sizeof(LIST_ENTRY*), NULL);
					        localRes = CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, (unsigned char*)current.Flink + sizeof(LIST_ENTRY*), &prevItemAddr, sizeof(LIST_ENTRY*), NULL);
	                    }
					    
	                    break;
	                }
	            }
	        }
			else
			{
				// Prevent infinite while looping. In most situations this code may be unnessecary.
				if (++retryCount == 3)
				{
					break;
				}
			}
			
			// Desired module was not yet found, traverse to the next one.
	        Node = curModule.InMemoryOrderModuleList.Flink;
	    }
	    while(Head != Node && moduleCount < mModuleManager->GetModuleCount());
	
		return found;
	}
	
	// Dumps a specific section in the loaded process to a file on the harddisk.
	// Returns true if the operation succeeded, and false if it did not succeed.
	bool PortableExecutable64::DumpProcessSection(const String& fileName, const SIZE_T address, const SIZE_T size) const
	{
		bool result = true;
		Byte* const buffer = new Byte[size];
		
		if (!CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(this->mBaseAddress + address), buffer, size, NULL))
		{
			result = false;
		}
		
		// Create dmp file on the disk.
		HANDLE hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			result = false;
		}
		
		// Write the data read to the file.
		DWORD bytesWritten;
		if (!WriteFile(hFile, buffer, (DWORD)size, &bytesWritten, NULL))
		{
			DeleteFile(fileName);
			result = false;
		}
		
		// All succeeded, free resources and return.
		CloseHandle(hFile);
		delete[] buffer;
		return result;
	}
	
	// Attempts to load a dynamic link library into the target process.
	// Returns true if the operation succeeded, and false if it did not succeed.
	bool PortableExecutable64::LoadLibraryExternal(const String& library) const
	{
		// Allocate memory space for the library path.
		void* const lpRemoteAddress = VirtualAllocEx(this->mProcessHandle, NULL, library.GetLength(), MEM_COMMIT, PAGE_READWRITE);
		SIZE_T bytesWritten;
		
		// Write path to library into the newly allocated memory.
		CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, lpRemoteAddress, library, library.GetLength(), &bytesWritten);
		if (bytesWritten != library.GetLength())
		{
			VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
			return false;
		}
		
		// Create a thread remotely that executes LoadLibraryA, pointing to the allocated string as parameter.
		HANDLE hThread = CreateRemoteThread(this->mProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA"), lpRemoteAddress, NULL, NULL);
		
		// Succesfully created thread, wait for it to complete and free resources after.
		if (hThread && hThread != INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(hThread, 5000);
			CloseHandle(hThread);
		}
		
		VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
		
		return !!hThread;
	}
	
	// Attempts to load a dynamic link library into the target process.
	// Returns true if the operation succeeded, and false if it did not succeed.
	bool PortableExecutable64::LoadLibraryExternalHijack(const String& library, HANDLE hThread) const
	{
		// If the thread wasn't opened, the function returns.
		if (!hThread || hThread == INVALID_HANDLE_VALUE)
		{
			return false;
		}
		
		// Allocate memory space for the library path.
		void* const lpRemoteAddress = VirtualAllocEx(this->mProcessHandle, NULL, library.GetLength(), MEM_COMMIT, PAGE_READWRITE);
		SIZE_T bytesWritten;
	
		// Write path to library into the newly allocated memory.
		CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, lpRemoteAddress, library, library.GetLength(), &bytesWritten);
		if (bytesWritten != library.GetLength())
		{
			VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
			return false;
		}
		
		// The shellcode that is written and executed inside the target program:
		// sub rsp, 8
		// mov dword ptr [rsp], 0xCCCCCCCC
		// mov dword ptr [rsp+4], 0xCCCCCCCC
		// push rax
		// push rbx
		// push rcx
		// push rdx
		// push r8
		// push r9
		// push r10
		// push r11
		// movabs rbx, 0xCCCCCCCCCCCCCCCC
		// movabs rcx, 0xCCCCCCCCCCCCCCCC
		// sub rsp, 32
		// call rbx
		// add rsp, 32
		// pop r11
		// pop r10
		// pop r9
		// pop r8
		// pop rdx
		// pop rcx
		// pop rbx
		// movabs rax, 0xCCCCCCCCCCCCCCCC
		// mov dword ptr [rax], 0x1337
		// pop rax
		// ret
		Byte shellCode[] = { 0x48, 0x83, 0xEC, 0x08, 0xC7, 0x04, 0x24, 0xCC, 0xCC, 0xCC, 0xCC, 0xC7, 0x44, 0x24, 0x04, 0xCC, 0xCC, 0xCC,
							 0xCC, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xBB, 0xCC, 0xCC, 0xCC,
							 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x83, 0xEC,
							 0x20, 0xFF, 0xD3, 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B,
							 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xC7, 0x00, 0x37, 0x13, 0x00, 0x00, 0x58, 0xC3 };
		
		// Allocate executable block of memory for the shellcode.
		void* const lpShellCode = VirtualAllocEx(this->mProcessHandle, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		const SIZE_T flagAddress = (SIZE_T)lpShellCode + 0x100;
		
		// Suspend the opened thread.
		SuspendThread(hThread);
		
		// Create context, aligned to 64-bits boundary for x64.
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT const ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		memset(ctx, 0, sizeof(CONTEXT));
		ctx->ContextFlags = CONTEXT_FULL;
		GetThreadContext(hThread, ctx);
		PLARGE_INTEGER rip64large = (PLARGE_INTEGER)&ctx->Rip;
		
		// Fix up dynamic addresses inside shellcode.
		*(DWORD*)&shellCode[7] = rip64large->LowPart;
		*(DWORD*)&shellCode[15] = rip64large->HighPart;
		*(SIZE_T*)&shellCode[33] = (SIZE_T)LoadLibraryA;
		*(SIZE_T*)&shellCode[43] = (SIZE_T)lpRemoteAddress;
		*(SIZE_T*)&shellCode[74] = flagAddress;
		
		// Write the shellcode to the remotely allocated buffer.
		CrySearchRoutines.CryWriteMemoryRoutine(this->mProcessHandle, lpShellCode, shellCode, sizeof(shellCode), &bytesWritten);
		if (bytesWritten != sizeof(shellCode))
		{
			VirtualFreeEx(this->mProcessHandle, lpShellCode, 0, MEM_RELEASE);
			VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
			return false;
		}
		
		// Change RIP to resume execution at the shellcode.
		ctx->Rip = (SIZE_T)lpShellCode;

		// Place the new context inside the thread.
		SetThreadContext(hThread, ctx);
		
		// Flush the instruction cache to avoid problems with cached instructions.
		FlushInstructionCache(this->mProcessHandle, lpShellCode, sizeof(shellCode));
		
		// Resume the thread to let the DLL load and close thread handle.
		ResumeThread(hThread);
		
		// Sample the completion flag to contain the magic number 0x1337. Block the thread until the sampling is succesful.
		DWORD magic = 0;
		do
		{
			CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)flagAddress, &magic, sizeof(DWORD), &bytesWritten);
			
			// Prevent CrySearch to start eating CPU time while still trying to have an accurate sample.
			Sleep(75);
		}
		while (magic != 0x1337);
		
		// The loop finished, free memory pages and close thread handle.
		VirtualFreeEx(this->mProcessHandle, lpShellCode, 0, MEM_RELEASE);
		VirtualFreeEx(this->mProcessHandle, lpRemoteAddress, 0, MEM_RELEASE);
		CloseHandle(hThread);
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		
		return !!hThread;
	}
	
	// Attempts to unload a loaded module from the target process.
	void PortableExecutable64::UnloadLibraryExternal(const SIZE_T module) const
	{
		// Create a thread remotely that executes FreeLibrary, with module handle as parameter.
		HANDLE hThread = CreateRemoteThread(this->mProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "FreeLibrary"), (void*)module, NULL, NULL);
		
		// Succesfully created thread, wait for it to complete and free resources after.
		if (hThread && hThread != INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(hThread, 5000);
			CloseHandle(hThread);
		}
	}
	
	// Restores the original address of an imported function from the export table.
	void PortableExecutable64::RestoreExportTableAddressImport(const Win32ModuleInformation* modBase, const SIZE_T baseAddress, const char* NameOrdinal, bool IsOrdinal) const
	{
		Byte* const dllBuffer = new Byte[0x400];
	    CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)baseAddress, dllBuffer, 0x400, NULL);
	   
	    const IMAGE_NT_HEADERS64* const pNTHeader =(IMAGE_NT_HEADERS64*)(dllBuffer + ((IMAGE_DOS_HEADER*)dllBuffer)->e_lfanew);
		IMAGE_DATA_DIRECTORY dataDir = *(&((IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	
	    delete[] dllBuffer;
	    
	    Byte* const exportDirectoryBuffer = new Byte[dataDir.Size];
	    CrySearchRoutines.CryReadMemoryRoutine(this->mProcessHandle, (void*)(baseAddress + dataDir.VirtualAddress), exportDirectoryBuffer, dataDir.Size, NULL);
	    
		Byte* const bufBase = exportDirectoryBuffer - dataDir.VirtualAddress;
		AddrStruct addrStruct((Byte*)baseAddress, (exportDirectoryBuffer - dataDir.VirtualAddress), bufBase + dataDir.VirtualAddress + dataDir.Size
			, &dataDir, (IMAGE_EXPORT_DIRECTORY*)exportDirectoryBuffer);
	    
		this->PlaceIATHook(modBase, NameOrdinal, this->GetAddressFromExportTable(&addrStruct, NameOrdinal, IsOrdinal), IsOrdinal);
		
		delete[] exportDirectoryBuffer;
	}
#endif