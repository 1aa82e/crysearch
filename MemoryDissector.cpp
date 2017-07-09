#include "MemoryDissector.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

// Default constructor of the MemoryDissector class.
MemoryDissector::MemoryDissector()
{
	this->mBaseAddress = 0;
	this->mRegionSize = 0;
}

// Default destructor of the MemoryDissector class.
MemoryDissector::~MemoryDissector()
{
	
}

// Retrieves the base address of the dissection entry.
const SIZE_T MemoryDissector::GetBaseAddress() const
{
	return (SIZE_T)this->mBaseAddress;
}

// Retrieves the size of the memory being dissected.
const DWORD MemoryDissector::GetRegionSize() const
{
	return this->mRegionSize;
}

// Returns the amount of rows currently in the dissection.
const int MemoryDissector::GetDissectionRowCount() const
{
	return this->mDissectionRows.GetCount();
}

// Starts dissection of the selected region of memory.
bool MemoryDissector::Dissect(const int rowOffset, const bool enableTypeGuessing)
{
	bool result = false;
	
	// Clear old dissection results.
	this->mDissectionRows.Clear();
	
	// Read the chunk of memory that the user defined.
	Byte* buffer = new Byte[this->mRegionSize];
	SIZE_T bytesRead;
	const BOOL b = CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)this->mBaseAddress, buffer, this->mRegionSize, &bytesRead);
	if (b && bytesRead == this->mRegionSize)
	{
		const Byte* endAddr = buffer + this->mRegionSize;
		unsigned int runnningOffset = 0;
		TYPE_GUESS_PARAMS params;
		params.PointerSize = mMemoryScanner->IsX86Process() ? sizeof(int) : sizeof(__int64);
		params.AddressLowerBound = mModuleManager->GetLowerBoundAddress();
		params.AddressUpperBound = mModuleManager->GetUpperBoundAddress();
		for (Byte* loop = buffer; loop < endAddr; )
		{
			// Guess the type if requested.
			params.Value = loop;
			params.MaxSize = endAddr - loop;
			const CCryDataType type = enableTypeGuessing ? GuessTypeOfValue(&params) : CRYDATATYPE_4BYTES;
			const int typeSize = type >= CRYDATATYPE_AOB ? params.OutDataLength : GetDataSizeFromValueType(type);
			
			// Add the dissection row accordingly.
			this->mDissectionRows.Add(DissectionRowEntry(runnningOffset, type, params.OutDataLength));
			
			// Complete iterations.
			loop += typeSize;
			runnningOffset += typeSize;
		}
		
		result = true;
	}

	// Free used resources.
	delete[] buffer;
	return result;
}

// Clears resources used by the previously executed dissection operation.
void MemoryDissector::Clear()
{
	this->mDissectionRows.Clear();
}

// Sets the base address of the dissection entry.
void MemoryDissector::SetBaseAddress(const SIZE_T addr)
{
	this->mBaseAddress = addr;
}

// Sets the size of the memory dissection.
void MemoryDissector::SetRegionSize(const DWORD regionSize)
{
	this->mRegionSize = regionSize;
}

// Sets the same dissection type for every loaded dissection row entry.
void MemoryDissector::SetGlobalDissectionType(const CCryDataType type)
{
	const int count = this->mDissectionRows.GetCount();
	for (int i = 0; i < count; ++i)
	{
		DissectionRowEntry& entry = this->mDissectionRows[i];
		entry.RowType = type;
		
		// We assume that this function is never called to change the global type to aob, string or wstring.
		entry.DataLength = 0;
	}
}