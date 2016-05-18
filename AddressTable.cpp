#include "AddressTable.h"
#include "BackendGlobalDef.h"

// Address table XML serialization logic.
void AddressTable::Xmlize(XmlIO& s)
{
	// Retrieve CrySearch's major and minor version number to flush into the file.
	WORD major;
	WORD minor;
	CrySearchGetMajorMinorVersion(&major, &minor);
	
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	String appnameStr = (char*)appname;
	
	String procName = mMemoryScanner->GetProcessName();
	
	// Write the address table to the XML serializer.
	s
		(appnameStr + "Version", Format("%i.%i", major, minor))
		("ProcessName", procName)
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

// Removes a set of entries from the address table.
void AddressTable::Remove(const Vector<int>& entries)
{
	this->mEntries.Remove(entries);
}

// Removes all address table entries from the address table.
void AddressTable::Clear()
{
	this->mEntries.Clear();
}

// Finds an entry in the table.
#ifdef _WIN64
	const int AddressTable::Find(const __int64 address, const CCryDataType valueType) const
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
	const int AddressTable::Find(const int address, const CCryDataType valueType) const
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
	outString = Format("%s+%lX", mModuleManager->GetModuleFilename(mod->BaseAddress), offset);
	
	// The function succeeded, return accordingly.
	return true;
}

// Adds / removes an entry in/from the address table.
#ifdef _WIN64
	AddressTableEntry* AddressTable::Add(const String& description, const __int64 address, const BOOLEAN IsRelative, const CCryDataType valueType)
	{
		AddressTableEntry ent;
		ent.Frozen = false;
		ent.Description = description;
		ent.Address = address;
		ent.ValueType = valueType;
		ent.IsRelative = IsRelative;

		// Address is relative. Try to retrieve the module name.
		if (IsRelative == TRUE)
		{
			// Retrieve the module that the address points into.
			const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(address);
			
			// If module was found, set module name.
			if (mod)
			{
				ent.ModuleName = mModuleManager->GetModuleFilename(mod->BaseAddress);
			}
		}

		return &(this->mEntries.Add(ent));
	}
	
	void AddressTable::Remove(const __int64 address, const CCryDataType valueType)
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
	AddressTableEntry* AddressTable::Add(const String& description, const int address, const BOOLEAN IsRelative, const CCryDataType valueType)
	{
		AddressTableEntry ent;
		ent.Frozen = false;
		ent.Description = description;
		ent.Address = address;
		ent.ValueType = valueType;
		ent.IsRelative = IsRelative;
		
		// Address is relative. Try to retrieve the module name.
		if (IsRelative == TRUE)
		{
			// Retrieve the module that the address points into.
			const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(address);
			
			// If module was found, set module name.
			if (mod)
			{
				ent.ModuleName = mModuleManager->GetModuleFilename(mod->BaseAddress);
			}
		}
		
		return &(this->mEntries.Add(ent));
	}
	
	void AddressTable::Remove(const int address, const CCryDataType valueType)
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

// ---------------------------------------------------------------------------------------------

// Resolves the address table entry as single entity.
void AddressTable::ResolveEntryRelative(AddressTableEntry* const entry)
{
	if (entry->IsRelative == TRUE)
	{
		// Resolve module base and calculate real address.
		const Win32ModuleInformation* const foundMod = mModuleManager->FindModule(entry->ModuleName);

		// If module was not found, for example when no process was opened, the application would crash.
		// This check prevents CrySearch from crashing. A process must be opened.
		if (foundMod)
		{
			entry->Address = foundMod->BaseAddress + entry->Address;
		}
		else
		{
			// It may be possible that saved relative entries do not resolve to a valid module upon load.
			// Resaving these entries will crash the application if they are saved as relatives.
			entry->IsRelative = ADDRESS_ENTRY_DANGLING;
		}
	}
	else if (entry->IsRelative == ADDRESS_ENTRY_DANGLING)
	{
		// When a process is loaded after the address table was opened, the entry is dangling.
		entry->IsRelative = TRUE;
		this->ResolveEntryRelative(entry);
	}
}

// Resolves relative address table entries to their associated module.
void AddressTable::ResolveRelativeEntries(AddressTable& at)
{
	const int aCount = at.GetCount();
	for (int i = 0; i < aCount; ++i)
	{
		// Resolve each entry seperately.
		at.ResolveEntryRelative(at[i]);
	}
}

// Creates an address table from a .csat XML data file.
void AddressTable::CreateAddressTableFromFile(AddressTable& at, const String& filename)
{
	// Load address table from persisted file.
	LoadFromXMLFile(at, filename);
	at.SetFileName(filename);
	
	// Resolve the addresses of relative entries.
	AddressTable::ResolveRelativeEntries(at);
}

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
		if (cur->IsRelative == TRUE)
		{
			// Set offset from module base as address before persisting.
			cur->Address = cur->Address - mModuleManager->FindModule(cur->ModuleName)->BaseAddress;
		}
	}
	
	// Persist address table to file.
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	String appnameStr = (char*)appname;
	StoreAsXMLFile(pTable, appnameStr + "AddressTable", filename);
	pTable.SetFileName(filename);
	
	// Restore temporary saved addresses in memory address table.
	for (int x = 0; x < aCount; ++x)
	{
		pTable[x]->Address = memAddresses[x];
	}
}