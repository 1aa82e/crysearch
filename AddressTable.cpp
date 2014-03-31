#include "AddressTable.h"

void AddressTable::Xmlize(XmlIO& s)
{
	s
		("ProcessName", this->mProcessName)
		("Entries", this->mEntries)
	;
}

AddressTable::AddressTable()
{
	
}

AddressTable::~AddressTable()
{
	
}

void AddressTable::Clear()
{
	this->mEntries.Clear();
	this->mEntries.Shrink();
}

#ifdef _WIN64
	const int AddressTable::Find(const __int64 address, const String& valueType) const
	{
		for (int i = 0; i < this->mEntries.GetCount(); i++)
		{
			if ((this->mEntries[i].Address == address) && this->mEntries[i].ValueType == valueType)
			{
				return i;
			}
		}
		
		return -1;
	}
#else
	const int AddressTable::Find(const int address, const String& valueType) const
	{
		for (int i = 0; i < this->mEntries.GetCount(); i++)
		{
			if ((this->mEntries[i].Address == address) && this->mEntries[i].ValueType == valueType)
			{
				return i;
			}
		}
		
		return -1;
	}

#endif

void AddressTable::SetProcessName(const String& pName)
{
	this->mProcessName = pName;
}

void AddressTable::ClearProcessName()
{
	this->mProcessName.Clear();
}

const int AddressTable::GetCount() const
{
	return this->mEntries.GetCount();
}

#ifdef _WIN64
	const AddressTableEntry* AddressTable::Add(const String& description, const __int64 address, const String& valueType)
	{
		AddressTableEntry ent;
		ent.Frozen = false;
		ent.Description = description;
		ent.Address = address;
		ent.ValueType = valueType;
		return &(this->mEntries.Add(ent));
	}
	
	void AddressTable::Remove(const __int64 address, const String& valueType)
	{
		for (int i = 0; i < this->mEntries.GetCount(); i++)
		{
			if (this->mEntries[i].Address == address && this->mEntries[i].ValueType == valueType)
			{
				this->mEntries.Remove(i);
				break;	
			}
		}
	}
#else
	const AddressTableEntry* AddressTable::Add(const String& description, const int address, const String& valueType)
	{
		AddressTableEntry ent;
		ent.Frozen = false;
		ent.Description = description;
		ent.Address = address;
		ent.ValueType = valueType;
		return &(this->mEntries.Add(ent));
	}
	
	void AddressTable::Remove(const int address, const String& valueType)
	{
		for (int i = 0; i < this->mEntries.GetCount(); i++)
		{
			if (this->mEntries[i].Address == address && this->mEntries[i].ValueType == valueType)
			{
				this->mEntries.Remove(i);
				break;	
			}
		}
	}
#endif

// Creates an address table from a .csat XML data file.
void AddressTable::CreateAddressTableFromFile(AddressTable& at, const String& filename)
{
	LoadFromXMLFile(at, filename);
}

// Creates an address table from a .ct Cheat Engine XML data file.
/*void AddressTable::CreateAddressTableFromCheatEngineFile(AddressTable& at, const String& filename)
{
	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	
	LARGE_INTEGER fs;
	GetFileSizeEx(hFile, &fs);
	
	char* fBuffer = new char[fs.LowPart];
	
	DWORD bytesRead;
	ReadFile(hFile, fBuffer, fs.LowPart, &bytesRead, NULL);
	
	if (bytesRead == fs.LowPart)
	{
		// Create XML parser and parse xml into memory structure.
		XmlParser xmp(fBuffer);
		
		while (!xmp.IsTag())
		{
			xmp.Skip();
		}
		
		// Enter root node.
		xmp.PassTag("CheatEntries");
		
		// Walk tags until a successor is hit.
		while (!xmp.IsEnd())
		{
			if (xmp.Tag("CheatEntries")
			{
				// new recursion
			}
			else if (xmp.Tag("Address"))
			{
				// new entry
			}
			else
			{
				xmp.Skip();
			}
		}
	}
	
	delete[] fBuffer;
	CloseHandle(hFile);
}*/

// Stores an in-memory address table to a .csat XML data file.
void AddressTable::SaveAddressTableToFile(AddressTable& pTable, const String& filename)
{
	StoreAsXMLFile(pTable, "CrySearchAddressTable", filename);
}