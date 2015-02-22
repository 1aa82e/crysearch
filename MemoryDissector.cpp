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
		int totalSteps = 0;
		for (Byte* loop = buffer; loop < endAddr; loop += rowOffset, totalSteps += rowOffset)
		{
			// The first dissection should have a default row size, or type guessing.
			const CCryDataType type = GuessTypeOfValue(loop);
			this->mDissectionRows.Add(DissectionRowEntry(totalSteps, type, 0));
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