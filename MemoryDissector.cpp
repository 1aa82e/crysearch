#include "MemoryDissector.h"
#include "GlobalDef.h"

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
	return this->mBaseAddress;
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
bool MemoryDissector::Dissect(const int rowOffset)
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
			this->mDissectionRows.Add(DissectionRowEntry(totalSteps, *(SIZE_T*)loop, rowOffset));
		}
		
		result = true;
	}

	// Free used resources.
	delete[] buffer;
	return result;
}

// Re-dissects a partial range of the existing dissection.
void MemoryDissector::DissectPartial(const Tuple2<int, int>& range)
{
	int i = range.a;
	SIZE_T customBase = this->mBaseAddress + this->mDissectionRows[i].RowOffset;
	unsigned int size = 0;
	
	// Calculate memory block to read.
	for (; i <= range.b; ++i)
	{
		size += this->mDissectionRows[i].RowSize;
	}
	
	// Read calculated memory block into local buffer.
	const DWORD endSz = size + sizeof(SIZE_T);
	Byte* buffer = new Byte[endSz];
	SIZE_T bytesRead;
	const BOOL b = CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)customBase, buffer, endSz, &bytesRead);
	if (b && bytesRead == endSz)
	{
		// Change values inside visible rows.
		size = 0;
		for (i = range.a; i <= range.b; ++i)
		{
			DissectionRowEntry* const row = &this->mDissectionRows[i];
			row->RowValue = *(SIZE_T*)(buffer + size);
			size += row->RowSize;
		}
	}
	
	// Free used resources.
	delete[] buffer;
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