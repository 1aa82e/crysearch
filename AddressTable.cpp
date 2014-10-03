#include "AddressTable.h"
#include "GlobalDef.h"

// Address table XML serialization logic.
void AddressTable::Xmlize(XmlIO& s)
{
	// Retrieve CrySearch's major and minor version number to flush into the file.
	WORD major;
	WORD minor;
	CrySearchGetMajorMinorVersion(&major, &minor);
	
	// Write the address table to the XML serializer.
	s
		("CrySearchVersion", Format("%i.%i", major, minor))
		("ProcessName", this->mProcessName)
		("Entries", this->mEntries)
		("MemoryDissections", this->mDissections)
	;
}

AddressTable::AddressTable()
{
	
}

AddressTable::~AddressTable()
{
	
}

// Removes all address table entries from the address table.
void AddressTable::Clear()
{
	this->mEntries.Clear();
	this->mEntries.Shrink();
}

// Finds an entry in the table.
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

// Sets the process name that will be saved in the file.
void AddressTable::SetProcessName(const String& pName)
{
	this->mProcessName = pName;
}

// Clears the process name saved in the file.
void AddressTable::ClearProcessName()
{
	this->mProcessName.Clear();
}

// Returns the amount of address table entries in the table.
const int AddressTable::GetCount() const
{
	return this->mEntries.GetCount();
}

// Returns the filename that the address table will save the file to.
const String& AddressTable::GetFileName() const
{
	return this->mSavedFileName;
}

// Sets the filename that the address table file will save the file to.
void AddressTable::SetFileName(const char* str)
{
	this->mSavedFileName = str;
}

// Retrieves a memory dissection entry at the specified index.
MemoryDissectionEntry* const AddressTable::GetDissection(const int index)
{
	return &this->mDissections[index];
}

// Tries to find a memory dissection entry by its base address.
// Returns a const pointer to the entry if it is found, or NULL otherwise.
/*const MemoryDissectionEntry* const AddressTable::FindDissectionByAddress(const SIZE_T address) const
{
	const int count = this->mDissections.GetCount();
	for (int i = 0; i < count; ++i)
	{
		if (this->mDissections[i].AssociatedDissector.GetBaseAddress() == address)
		{
			return &this->mDissections[i];
		}
	}
	
	return NULL;
}*/

// Gets the amount of dissection entries currently in the address table.
const int AddressTable::GetDissectionCount() const
{
	return this->mDissections.GetCount();
}

// Adds a new memory dissection entry to the address table.
void AddressTable::AddDissection(const char* pFriendlyName, const SIZE_T baseAddress, const DWORD memorySize)
{
	this->mDissections.Add(MemoryDissectionEntry(pFriendlyName, baseAddress, memorySize));
}

// Removes a memory dissection entry from the address table and destroys associated resources.
void AddressTable::RemoveDissection(const int index)
{
	// Remove the dissection entry from the list.
	this->mDissections.Remove(index);
}

// Retrieves the module base and address table entry address and constructs a UI showable representation.
const bool AddressTable::GetRelativeDisplayString(const AddressTableEntry* entry, String& outString)
{
	// Retrieve the module that the address points into.
	const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(entry->Address);
	
	// If the address did not point into a module the function should return false.
	if (!mod)
	{
		return false;
	}
	
	// Still here, so calculate the offset.
	const LONG_PTR offset = entry->Address - mod->BaseAddress;
	outString = Format("%s+%lX", mod->ModuleName, offset);
	
	// The function succeeded, return accordingly.
	return true;
}

// Adds / removes an entry in/from the address table.
#ifdef _WIN64
	AddressTableEntry* AddressTable::Add(const String& description, const __int64 address, const bool IsRelative, const String& valueType)
	{
		AddressTableEntry ent;
		ent.Frozen = false;
		ent.Description = description;
		ent.Address = address;
		ent.ValueType = valueType;
		ent.IsRelative = IsRelative;

		// Address is relative. Try to retrieve the module name.
		if (IsRelative)
		{
			// Retrieve the module that the address points into.
			const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(address);
			
			// If module was found, set module name.
			if (mod)
			{
				ent.ModuleName = mod->ModuleName;
			}
		}

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
	AddressTableEntry* AddressTable::Add(const String& description, const int address, const bool IsRelative, const String& valueType)
	{
		AddressTableEntry ent;
		ent.Frozen = false;
		ent.Description = description;
		ent.Address = address;
		ent.ValueType = valueType;
		ent.IsRelative = IsRelative;
		
		// Address is relative. Try to retrieve the module name.
		if (IsRelative)
		{
			// Retrieve the module that the address points into.
			const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(address);
			
			// If module was found, set module name.
			if (mod)
			{
				ent.ModuleName = mod->ModuleName;
			}
		}
		
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
	// Load address table from persisted file.
	LoadFromXMLFile(at, filename);
	at.SetFileName(filename);
	
	// Resolve the addresses of relative entries.
	const int aCount = at.GetCount();
	for (int i = 0; i < aCount; ++i)
	{
		AddressTableEntry* const cur = at[i];
		if (cur->IsRelative)
		{
			// Resolve module base and calculate real address.
			const Win32ModuleInformation* const foundMod = mModuleManager->FindModule(cur->ModuleName);

			// If module was not found, for example when no process was opened, the application would crash.
			// This check prevents CrySearch from crashing. A process must be opened.
			if (foundMod)
			{
				cur->Address = foundMod->BaseAddress + cur->Address;
			}
		}
	}
}

// Cheat table entry recursion function.
/*void CheatEntry(XmlParser& xmp, AddressTable& at)
{
	// If a CheatEntries tag is found, a new recursion is necessary.
	if (xmp.Tag("CheatEntries"))
	{
		CheatEntry(xmp, at);
	}

	// If a CheatEntry tag is found
	else if (xmp.Tag("CheatEntry"))
	{
		// Save the description of the cheat table entry. The recursion choice is always after.
		String desc;
		if (xmp.LoopTag("Description"))
		{
			desc = xmp.ReadText();
			xmp.SkipEnd();
			desc.Replace("\"", "");
		}
		
		// Loop until next decisional tag is found.
		String nextTag = xmp.ReadTag();
		for (; nextTag.Compare("CheatEntries") != 0 && nextTag.Compare("VariableType") != 0; )
		{
			xmp.SkipEnd();
			nextTag = xmp.ReadTag();
		}
		
		// Act adequately to the found decisional tag.
		if (nextTag.Compare("CheatEntries") == 0)
		{
			CheatEntry(xmp, at);
		}
		else
		{
			// Retrieve variable data type and try to retrieve address.
			String varType = xmp.ReadText();
			xmp.SkipEnd();
			if (xmp.Tag("Address"))
			{
				// Every field except the offsets has been acquired. Create entry.
				String addr = xmp.ReadText();
				addr.Replace("\"", "");
				bool unicode = false;
				
				// Try to retrieve unicode-ness of string values.
				xmp.SkipEnd();
				if (xmp.Tag("Unicode"))
				{
					unicode = !!StrInt(xmp.ReadText());
				}

#ifdef _WIN64
				AddressTableEntry* newEntry = at.Add(desc, ScanInt64(addr, NULL, 16), false, GetCrySearchValueTypeFromCheatTableVariableType(varType, unicode));
#else
				AddressTableEntry* newEntry = at.Add(desc, ScanInt(addr, NULL, 16), false, GetCrySearchValueTypeFromCheatTableVariableType(varType, unicode));
#endif
				
				// Try to retrieve the length of the string or array of bytes value.
				xmp.SkipEnd();
				if (xmp.Tag("Length"))
				{
					newEntry->Size = StrInt(xmp.ReadText());
				}
				
				// Try to retrieve offsets.
				xmp.SkipEnd();
				if (xmp.Tag("Offsets"))
				{
					// Loop offsets.
					while (!xmp.End())
					{
						if (xmp.TagE("Offset"))
						{
							newEntry->OffsetsList.Add(ScanInt(xmp.GetPtr(), NULL, 16));
						}
					}
				}
			}
			else
			{
				xmp.Skip();
			}
		}
	}
	else
	{
		xmp.Skip();
	}
}

// Creates an address table from a .ct Cheat Engine XML data file.
bool AddressTable::CreateAddressTableFromCheatEngineFile(AddressTable& at, const String& filename)
{
	// Clear the address table.
	at.Clear();
	
	// Open Cheat-Engine table file.
	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	
	// Get file size.
	LARGE_INTEGER fs;
	GetFileSizeEx(hFile, &fs);
	char* fBuffer = new char[fs.LowPart];
	
	// Read file contents into locally allocated buffer.
	DWORD bytesRead;
	ReadFile(hFile, fBuffer, fs.LowPart, &bytesRead, NULL);
	
	// The file doesn't need to be open any longer.
	CloseHandle(hFile);
	
	// File was succesfully read. Check if it actually could be an XML file to avoid retard behavior.
	if ((bytesRead == fs.LowPart) && (*(WORD*)fBuffer == 0x3F3C))
	{
		// Create XML parser and parse xml into memory structure.
		XmlParser xmp(fBuffer);
		
		try
		{
			// Skip declaration(s).
			while (!xmp.IsTag())
			{
				xmp.Skip();
			}
			
			// Try to find the root tag.
			xmp.PassTag("CheatTable");
			
			// Loop until the end CheatTable tag was found.
			while (!xmp.End())
			{
				CheatEntry(xmp, at);
			}
		}
		catch (XmlError exc)
		{
			// The first tag was not succesfully passed, meaning the XML file is not correct.
			delete[] fBuffer;
			return false;
		}
	}
	else
	{
		// Delete the allocated buffer.
		delete[] fBuffer;
		
		// File was not read succesfully or not valid.
		return false;
	}
	
	// Delete the allocated buffer.
	delete[] fBuffer;
	
	// Cheat table was succesfully loaded.
	return true;
}*/

// Stores an in-memory address table to a .csat XML data file.
void AddressTable::SaveAddressTableToFile(AddressTable& pTable, const String& filename)
{
	const int aCount = pTable.GetCount();
	
	// Temporary vector container to hold addresses to restore when the address table is saved.
	// If we don't do this, the addresses are replaced in memory.
	Vector<LONG_PTR> memAddresses;
	memAddresses.Reserve(aCount);
	
	// Convert real runtime addresses of relative entries to offsets.
	for (int i = 0; i < aCount; ++i)
	{
		AddressTableEntry* const cur = pTable[i];
		
		// Save memory held address in temporary storage to prevent inconsistency.
		memAddresses << cur->Address;
		
		// If the address is relative it should be recalculated to the file.
		if (cur->IsRelative)
		{
			// Set offset from module base as address before persisting.
			cur->Address = cur->Address - mModuleManager->FindModule(cur->ModuleName)->BaseAddress;
		}
	}
	
	// Persist address table to file.
	StoreAsXMLFile(pTable, "CrySearchAddressTable", filename);
	pTable.SetFileName(filename);
	
	// Restore temporary saved addresses in memory address table.
	for (int x = 0; x < aCount; ++x)
	{
		pTable[x]->Address = memAddresses[x];
	}
}
