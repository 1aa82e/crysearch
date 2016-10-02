#ifndef _CrySearch_PortableExecutable_h_
#define _CrySearch_PortableExecutable_h_

#include <Core/Core.h>

using namespace Upp;

#include "ProcessUtil.h"

// Represents a section within a PE executable file.
struct Win32PESectionInformation : Moveable<Win32PESectionInformation>
{
	String SectionName;
	SIZE_T BaseAddress;
	SIZE_T SectionSize;
	SIZE_T RawSectionSize;
	
	// Parameter constructor because of the single initialization point, preventing feature envy detections.
	Win32PESectionInformation(const char* pName, const SIZE_T pBaseAddr, const SIZE_T pSectionSize, const SIZE_T pRawSize)
	{
		this->SectionName = pName;
		this->BaseAddress = pBaseAddr;
		this->SectionSize = pSectionSize;
		this->RawSectionSize = pRawSize;
	};
};

// Represents a section within a .NET executable file.
struct Win32DotNetSectionInformation : Moveable<Win32DotNetSectionInformation>
{
	String SectionName;
	LONG Offset;
	LONG Size;
};

// Represents the type of machine a PE executable should run on.
enum PEMachineType
{
	I386,
	IA_64,
	AMD64
};

// IAT function entry flags.
#define IAT_FLAG_HOOKED		1
#define IAT_FLAG_NOT_FOUND	2

// Represents an entry in the import address table.
// FunctionName:		Foreign name of the function, declared in export address table and shown in import address table;
// Ordinal:				2-byte ordinal value that locates an imported function in the export address table of a module;
// VirtualAddress:		The virtual address (runtime, not RVA), of the imported function;
// Hint:				2-byte hint that is used by linkers and PE loaders to increase performance of lookup operations.
struct ImportAddressTableEntry : Moveable<ImportAddressTableEntry>
{
	String FunctionName;
	SIZE_T VirtualAddress;
	WORD Ordinal;
	WORD Hint;
	
	// Flag field can be either 0, IAT_FLAG_HOOKED.
	Byte Flag;
	
	// We want to resolve intermodular calls to imported functions. To do so, we need the
	// address of the thunk table of imported functions as well.
	SIZE_T ThunkAddress;
};

// Represents an import table descriptor item, identifying a module with functions.
struct ImportTableDescriptor : Moveable<ImportTableDescriptor>
{
	String ModuleName;
	Vector<ImportAddressTableEntry> FunctionList;
	
	// Logical base address of a possibly virtualized API. If the module is not virtualized, this field is 0.
	SIZE_T LogicalBaseAddress;
	
	unsigned GetHashValue() const
	{
		return this->ModuleName.GetHashValue();
	}
};

// Contains data about a .NET executable header and sections.
struct Win32DotNetInformation
{
	DWORD MetadataHeaderOffset;
	Vector<Win32DotNetSectionInformation> DotNetSections;
};

// Represents a pointable struct that contains all PE information of a loaded process.
struct Win32PEInformation
{
	VectorMap<String, Value> PEFields;
	Win32DotNetInformation DotNetInformation;
	Vector<Win32PESectionInformation> ImageSections;
	Vector<ImportTableDescriptor> ImportAddressTable;
	
	// Clears everything except the import address table in this instance.
	void Reset()
	{
		this->PEFields.Clear();
		this->ImageSections.Clear();
		this->DotNetInformation.DotNetSections.Clear();
	};
	
	// Clears the import address table in this instance.
	void ClearImportTable()
	{
		this->ImportAddressTable.Clear();
	};
	
	// Looks for an imported function at a specified address.
	const bool FindImportedFunctionAddress(const SIZE_T address, String& function) const
	{
		// Walk through the import table descriptors.
		for (auto const& iat : this->ImportAddressTable)
		{
			// Walk through the functions in this descriptor.
			for (auto const& f : iat.FunctionList)
			{
				// Check whether a function in the function list matches the specified address.
				if (f.ThunkAddress == address)
				{
					function = iat.ModuleName + "!" + f.FunctionName;
					return true;
				}
			}
		}
		
		// No function was found at the specified address.
		return false;
	};
};

// Address struct for holding addresses. Pointer to this struct is passed to PE functions that needs them.
// BaseAddress:			The base address of the module with the export table in memory;
// BufferBaseAddress:	The address of the buffer, relative to the base (- 0x1000 for PE32);
// BufferEndAddress		The address totalling the base address, reaching until the end of the export directory;
// DirectoryAddress:	The address of the data directory in local memory;
// ExportDirectory:		The address of the export directory in local memory.
struct AddrStruct
{
	Byte* BaseAddress;
	Byte* BufferBaseAddress;
	Byte* BufferEndAddress;
	IMAGE_DATA_DIRECTORY* DirectoryAddress;
	IMAGE_EXPORT_DIRECTORY* ExportDirectory;
	
	// To reduce construction code clumps in the PortableExecutable classes, parameter constructor.
	AddrStruct(Byte* const pBase, Byte* const pBufferBase, Byte* const pBufferEnd, IMAGE_DATA_DIRECTORY* const pDirAddr, IMAGE_EXPORT_DIRECTORY* const pExpDir)
	{
		this->BaseAddress = pBase;
		this->BufferBaseAddress = pBufferBase;
		this->BufferEndAddress = pBufferEnd;
		this->DirectoryAddress = pDirAddr;
		this->ExportDirectory = pExpDir;
	};
};

// PE base class
class PortableExecutable
{
protected:
	HANDLE mProcessHandle;
	SIZE_T mBaseAddress;
	
	void GetDotNetDirectoryInformation(const IMAGE_DATA_DIRECTORY* const netHeader) const;
	
	virtual const char* GetOrdinalFunctionNameFromExportTable(const AddrStruct* addr, const WORD ordinal) const = 0;
public:
	virtual void GetExecutablePeInformation() const = 0;
	virtual void GetImportAddressTable() const = 0;
	virtual bool PlaceIATHook(const Win32ModuleInformation* modBase, const char* NameOrdinal, const SIZE_T newAddress, bool IsOrdinal) const = 0;
	virtual bool RestorePEHeaderFromFile(const String& fileName, const Win32ModuleInformation& module) const = 0;
	virtual bool HideModuleFromProcess(const Win32ModuleInformation& module) const = 0;
	virtual bool DumpProcessSection(const String& fileName, const SIZE_T address, const SIZE_T size) const = 0;
	virtual bool LoadLibraryExternal(const String& library) const = 0;
	virtual bool LoadLibraryExternalHijack(const String& library, HANDLE hThread) const = 0;
	virtual void UnloadLibraryExternal(const SIZE_T module) const = 0;
	virtual void RestoreExportTableAddressImport(const Win32ModuleInformation* modBase, const SIZE_T baseAddress, const char* NameOrdinal, bool IsOrdinal) const = 0;
	virtual SIZE_T GetAddressFromExportTable(const AddrStruct* addr, const char* NameOrdinal, const unsigned int NameLength) const = 0;
	
	wchar* ResolveApiSetSchemaMapping(const wchar* ApiSetSchemaDll, const DWORD Length) const;
	wchar* ResolveApiSetSchemaMappingEx(const wchar* ApiSetSchemaDll, const DWORD Length) const;
	wchar* ResolveApiSetSchemaMapping10(const wchar* ApiSetSchemaDll, const DWORD Length ) const;
	
	__declspec(noinline) void ParseSubsystemValue(const DWORD subSystem) const;
	__declspec(noinline) void ParseMachineType(const DWORD machineType) const;
	__declspec(noinline) void GetImageSectionsList(const IMAGE_SECTION_HEADER* pSecHeader, const DWORD numberOfSections, Vector<Win32PESectionInformation>& list) const;
	
	wchar* InlineResolveApiSetSchema(const WString& str) const;
	const Win32ModuleInformation* GetResolvedModule(const Byte* bufferBase, int* const recurseIndex, const DWORD* funcPtr, const char* NameOrdinal) const;
	
	void* GetPebAddress() const;
	
	// Small methods to set the internal variables.
	void SetBaseAddress(const SIZE_T baseAddress);
	const SIZE_T GetBaseAddress() const;

	PortableExecutable();
	virtual ~PortableExecutable();
};

// PE32
class PortableExecutable32 : public PortableExecutable
{
protected:
	virtual const char* GetOrdinalFunctionNameFromExportTable(const AddrStruct* addr, const WORD ordinal) const;
public:
	virtual void GetExecutablePeInformation() const override final;
	virtual void GetImportAddressTable() const override final;
	virtual bool PlaceIATHook(const Win32ModuleInformation* modBase, const char* NameOrdinal, const SIZE_T newAddress, bool IsOrdinal) const override final;
	virtual bool RestorePEHeaderFromFile(const String& fileName, const Win32ModuleInformation& module) const override final;
	virtual bool HideModuleFromProcess(const Win32ModuleInformation& module) const override final;
	virtual bool DumpProcessSection(const String& fileName, const SIZE_T address, const SIZE_T size) const override final;
	virtual bool LoadLibraryExternal(const String& library) const override final;
	virtual bool LoadLibraryExternalHijack(const String& library, HANDLE hThread) const override final;
	virtual void UnloadLibraryExternal(const SIZE_T module) const override final;
	virtual void RestoreExportTableAddressImport(const Win32ModuleInformation* modBase, const SIZE_T baseAddress, const char* NameOrdinal, bool IsOrdinal) const override final;
	virtual SIZE_T GetAddressFromExportTable(const AddrStruct* addr, const char* NameOrdinal, const unsigned int NameLength) const override final;
	
	PortableExecutable32() : PortableExecutable() { }
	~PortableExecutable32();
};

// PE64
#ifdef _WIN64
	class PortableExecutable64 : public PortableExecutable
	{
	protected:
		virtual const char* GetOrdinalFunctionNameFromExportTable(const AddrStruct* addr, const WORD ordinal) const;
	public:
		virtual void GetExecutablePeInformation() const override final;
		virtual void GetImportAddressTable() const override final;
		virtual bool PlaceIATHook(const Win32ModuleInformation* modBase, const char* NameOrdinal, const SIZE_T newAddress, bool IsOrdinal) const override final;
		virtual bool RestorePEHeaderFromFile(const String& fileName, const Win32ModuleInformation& module) const override final;
		virtual bool HideModuleFromProcess(const Win32ModuleInformation& module) const override final;
		virtual bool DumpProcessSection(const String& fileName, const SIZE_T address, const SIZE_T size) const override final;
		virtual bool LoadLibraryExternal(const String& library) const override final;
		virtual bool LoadLibraryExternalHijack(const String& library, HANDLE hThread) const override final;
		virtual void UnloadLibraryExternal(const SIZE_T module) const override final;
		virtual void RestoreExportTableAddressImport(const Win32ModuleInformation* modBase, const SIZE_T baseAddress, const char* NameOrdinal, bool IsOrdinal) const override final;
		virtual SIZE_T GetAddressFromExportTable(const AddrStruct* addr, const char* NameOrdinal, const unsigned int NameLength) const override final;
		
		PortableExecutable64() : PortableExecutable() { }
		~PortableExecutable64();
	};
#endif

#endif