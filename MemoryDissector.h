#ifndef _CrySearch_MemoryDissector_h_
#define _CrySearch_MemoryDissector_h_

#include <Core/Core.h>

using namespace Upp;

#include "CrySearchLibrary/SDK/CrySearch.h"

// Represents a row of dissection in an available dissection.
struct DissectionRowEntry : Moveable<DissectionRowEntry>
{
	int RowOffset;
	Value RowValue;
	CCryDataType RowType;
	
	// The data length is only applicable for AOB, string or wstring types.
	int DataLength;
	
	// Default constructor to add new entry straight to vector.
	DissectionRowEntry(const int rowOffset, const char* val, const int rowType, const int length)
	{
		this->RowOffset = rowOffset;
		this->RowValue = val;
		this->RowType = rowType;
		this->DataLength = length;
	};
};

// Represents a memory dissector. Keeps track of dissected entries and applies operations on it.
// Every available dissection has a memory dissector associated.
class MemoryDissector
{
private:
	SIZE_T mBaseAddress;
	DWORD mRegionSize;
	Vector<DissectionRowEntry> mDissectionRows;
	
	friend struct MemoryDissectionEntry;
public:
	MemoryDissector();
	~MemoryDissector();
	
	const SIZE_T GetBaseAddress() const;
	const DWORD GetRegionSize() const;
	const int GetDissectionRowCount() const;
	
	bool Dissect(const int rowOffset);
	void DissectPartial(const Tuple2<int, int>& range);
	void Clear();
	
	void SetBaseAddress(const SIZE_T addr);
	void SetRegionSize(const DWORD regionSize);
	void SetGlobalDissectionType(const CCryDataType type);
	
	DissectionRowEntry* operator[] (const int index)
	{
		return &this->mDissectionRows[index];
	};
};

#endif