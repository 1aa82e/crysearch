#ifndef _CrySearch_AddressTable_h_
#define _CrySearch_AddressTable_h_

#pragma warning(disable : 4005)

#include <Core/Core.h>

using namespace Upp;

#include "MemoryDissector.h"

// ---------------------------------------------------------------------------------------------

// When a relative address table entry was not succesfully resolved, it should be still written
// back to the address table file as if it was never changed. This indication value helps
// CrySearch know when a dangling entry is the case.
#define ADDRESS_ENTRY_DANGLING (BOOLEAN)0xFF

// Represents an entry in the user defined address list.
struct AddressTableEntry : Moveable<AddressTableEntry>
{
	// Represents the description of the address table entry.
	// The description is non-trivial and may be empty regardless of the situation.
	String Description;
	
	// Represents the address of the address table entry. The address should be valid.
#ifdef _WIN64
	__int64 Address;
#else
	int Address;
#endif
	
	// Indicates whether the address table entry resolves to a relative address. This field
	// is considered leading information for a great part of the address table behavior.
	BOOLEAN IsRelative;
	
	// If the address is relative the module name should be saved in order to be able to
	// resolve the real address at runtime. This field contains the module name.
	String ModuleName;
	
	// Contains the offsets that are configured for this address table entry.
	// This field is considered leading information for a great part of the address table behavior.
	Vector<int> OffsetsList;
	
	// Represents the value type of the address table entry. This field is trivial and 
	// is considered leading information for a great part of the address table behavior.
	CCryDataType ValueType;
	
	// Represents the value of the address table entry. This field contains the user interface
	// representation of the value because it is not persisted in the file.
	mutable String Value;
	
	// Indicates whether the address table entry is frozen or not. This field is considered
	// leading information for a small part of the address table behavior.
	bool Frozen;
	
	// This parameter represents the length of a byte array or string. When one of these types are not used, this parameter is ignored.
	mutable int Size;
	
	// XML serialization logic function.
	void Xmlize(XmlIO& s)
	{
		// Upon loading, this will always be either TRUE or FALSE. Upon saving, an entry may be dangling.
		// If it is dangling, it should be saved as relative.
		if (this->IsRelative == ADDRESS_ENTRY_DANGLING)
		{
			this->IsRelative = TRUE;
		}
		
		// Serialize address table entry to file.
		s
			("Description", this->Description)
			("Address", this->Address)
			("IsRelative", this->IsRelative)
			("ModuleName", this->ModuleName)
			("OffsetsList", this->OffsetsList)
			("ValueType", this->ValueType)
			("Frozen", this->Frozen)
			("Size", this->Size)
		;
	};
	
	// Default address table entry constructor.
	AddressTableEntry()
	{
		this->ValueType = CRYDATATYPE_4BYTES;
		this->Size = 0;
		this->Frozen = false;
		this->Address = 0;
	};
	
	// Default copy constructor. Needed for vector containment.
	AddressTableEntry(const AddressTableEntry& entry)
	{
		this->ValueType = entry.ValueType;
		this->Size = entry.Size;
		this->Frozen = entry.Frozen;
		this->Address = entry.Address;
		this->Value = entry.Value;
		this->IsRelative = entry.IsRelative;
		this->ModuleName = entry.ModuleName;
		this->OffsetsList.Append(entry.OffsetsList);
	};
};

// Represents a memory dissection entry that can be altered from the memory dissection window.
struct MemoryDissectionEntry : Moveable<MemoryDissectionEntry>
{
	// Represents the friendly name of the dissection.
	String FriendlyName;
	
	// The memory dissector operator class associated to this dissection entry.
	// The operator class manages the base address.
	MemoryDissector AssociatedDissector;
	
	// Default constructor.
	MemoryDissectionEntry()
	{
		
	};
	
	// Default copy constructor.
	MemoryDissectionEntry(const MemoryDissectionEntry& copy)
	{
		this->FriendlyName = copy.FriendlyName;
		this->AssociatedDissector.SetBaseAddress(copy.AssociatedDissector.GetBaseAddress());
		this->AssociatedDissector.SetRegionSize(copy.AssociatedDissector.GetRegionSize());
		this->AssociatedDissector.mDissectionRows.Append(copy.AssociatedDissector.mDissectionRows);
	}
	
	// Default constructor with parameters.
	MemoryDissectionEntry(const char* pFriendlyName, const SIZE_T baseAddress, const DWORD memorySize)
	{
		this->FriendlyName = pFriendlyName;
		this->AssociatedDissector.SetBaseAddress(baseAddress);
		this->AssociatedDissector.SetRegionSize(memorySize);
	};	
	
	// XML serialization logic function.
	void Xmlize(XmlIO& s)
	{
		s
			("FriendlyName", this->FriendlyName)
			
			// I don't really like this construction but it is the way to a correct compiler interpretation on x64.
#ifdef _WIN64
			("BaseAddress", (LONG_PTR&)this->AssociatedDissector.mBaseAddress)
#else
			("BaseAddress", this->AssociatedDissector.mBaseAddress)
#endif
			("MemorySize", this->AssociatedDissector.mRegionSize)
		;
	};
};

// Represents an address table.
class AddressTable
{
private:
	String mSavedFileName;
	String mProcessName;
	Vector<AddressTableEntry> mEntries;
	Vector<MemoryDissectionEntry> mDissections;
public:
	AddressTable();
	~AddressTable();
	void Xmlize(XmlIO& s);
	
#ifdef _WIN64
	void Remove(const __int64 address, const CCryDataType valueType);
	AddressTableEntry* Add(const String& description, const __int64 address, const BOOLEAN IsRelative, const CCryDataType valueType);
	const int Find(const __int64 address, const CCryDataType valueType) const;
#else
	void Remove(const int address, const CCryDataType valueType);
	AddressTableEntry* Add(const String& description, const int address, const BOOLEAN IsRelative, const CCryDataType valueType);
	const int Find(const int address, const CCryDataType valueType) const;
#endif
	
	void Clear();
	void SetProcessName(const String& pName);
	void ClearProcessName();
	void SetFileName(const char* str);
	
	const int GetCount() const;
	const String& GetFileName() const;
	const bool GetRelativeDisplayString(const AddressTableEntry* entry, String& outString);
	
	const AddressTableEntry* operator [] (const int x) const
	{
		return &(this->mEntries[x]);
	};
	
	AddressTableEntry* operator [] (const int x)
	{
		return &(this->mEntries[x]);
	};
	
	MemoryDissectionEntry* const GetDissection(const int index);
	const int GetDissectionCount() const;

	void AddDissection(const char* pFriendlyName, const SIZE_T baseAddress, const DWORD memorySize);
	void RemoveDissection(const int index);
	void ResolveEntryRelative(AddressTableEntry* const entry);
	
	static void ResolveRelativeEntries(AddressTable& at);
	static void CreateAddressTableFromFile(AddressTable& at, const String& filename);
	//static bool CreateAddressTableFromCheatEngineFile(AddressTable& at, const String& filename);
	static void SaveAddressTableToFile(AddressTable& pTable, const String& filename);
};

#endif