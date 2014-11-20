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
			// The first dissection should have a default row size, or type guessing.
			this->mDissectionRows.Add(DissectionRowEntry(totalSteps, ValueAsStringInternal(loop, CRYDATATYPE_4BYTES, 0), CRYDATATYPE_4BYTES, 0));
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
		size += GetDataSizeFromValueType(this->mDissectionRows[i].RowType);
	}
	
	// Read calculated memory block into local buffer.
	// sizeof(SIZE_T) bytes are added to avoid the user interface from flickering in the last three rows.
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
			row->RowValue = ValueAsStringInternal(buffer + size, row->RowType, row->DataLength);
			size += row->DataLength > 0 ? row->DataLength : GetDataSizeFromValueType(row->RowType);
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