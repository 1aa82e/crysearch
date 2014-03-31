#ifndef _CrySearch_AddressTable_h_
#define _CrySearch_AddressTable_h_

#pragma warning(disable : 4005)

#include <Core/Core.h>

using namespace Upp;

// Represents an entry in the user defined address list.
struct AddressTableEntry : Moveable<AddressTableEntry>
{
	String Description;
#ifdef _WIN64
	__int64 Address;
#else
	int Address;
#endif
	String ValueType;
	mutable String Value;
	mutable bool Frozen;
	
	// This parameter represents the length of a byte array or string. When one of these types are not used, this parameter is ignored.
	mutable int Size;
	
	void Xmlize(XmlIO& s)
	{
		s
			("Description", Description)
			("Address", Address)
			("ValueType", ValueType)
			("Frozen", Frozen)
			("Size", Size)
		;
	}
	
	AddressTableEntry()
	{
		this->ValueType = "4 Bytes";
		this->Size = 0;
		this->Frozen = false;
		this->Address = 0;
	}
};

// Represents an address list.
class AddressTable sealed
{
private:
	String mProcessName;
	Vector<AddressTableEntry> mEntries;
public:
	AddressTable();
	~AddressTable();
	void Xmlize(XmlIO& s);
	
#ifdef _WIN64
	void Remove(const __int64 address, const String& valueType);
	const AddressTableEntry* Add(const String& description, const __int64 address, const String& valueType);
	const int Find(const __int64 address, const String& valueType) const;
#else
	void Remove(const int address, const String& valueType);
	const AddressTableEntry* Add(const String& description, const int address, const String& valueType);
	const int Find(const int address, const String& valueType) const;
#endif
	void Clear();
	void SetProcessName(const String& pName);
	void ClearProcessName();
	
	const int GetCount() const;
	
	const AddressTableEntry* operator [] (const int x) const
	{
		return &(this->mEntries[x]);
	};
	
	AddressTableEntry* operator [] (const int x)
	{
		return &(this->mEntries[x]);
	}
	
	static void CreateAddressTableFromFile(AddressTable& at, const String& filename);
	//static void CreateAddressTableFromCheatEngineFile(AddressTable& at, const String& filename);
	static void SaveAddressTableToFile(AddressTable& pTable, const String& filename);
};

#endif
