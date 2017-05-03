#ifndef _CrySearch_MemoryScannerIO_h_
#define _CrySearch_MemoryScannerIO_h_

// The file header storing information about the worker and file contents.
struct StorageFileHeader
{
	// Indicates which worker this file belongs to.
	int WorkerId;
	
	// Indicates the number of storage blocks in this file.
	unsigned int BlockCount;
	
	// Default initialization constructor.
	StorageFileHeader()
	{
		this->WorkerId = 0;
		this->BlockCount = 0;
	};
	
	// Default constructor to simplify basic construction.
	StorageFileHeader(const int worker)
	{
		this->WorkerId = worker;
		this->BlockCount = 0;
	};
};

// Represents a disk storage structure header for the memory scanner.
struct MemoryRegionFileHeader
{
	// Identifies the page in CrySearch memory.
	unsigned int PageIndex;
	
	// Identifies the base address of the page.
	SIZE_T BaseAddress;
	
	// Indicates the distance (alignment) in bytes between addresses in the storage block.
	unsigned int AddressOffsetAlignment;
	
	// Indicates the number of search results in this block.
	unsigned int AddressCount;
	
	// Represents the number of value results in this block (ofcourse located in another file).
	unsigned int ValueCount;
	
	// Indicates where the value sequence for these results start in the value files.
	unsigned int ValueStorageIndex;
	
	// Indicates the size of this storage block on the disk including the header size. This
	// size can be at most the maximum configured blocksize. If the storage block exceeds
	// that size, a new block will have its base address start at the remaining storage.
	SIZE_T SizeInBytes;
	
	// Internal Bits allocation variable. It needs to be stored because it reconstructs the Bits.
	int BitsInternalAlloc;
	
	MemoryRegionFileHeader() { };
	
	// Default constructor to simplify constructing a basic storage header.
	MemoryRegionFileHeader(const unsigned int pageIndex, const SIZE_T baseAddress, const unsigned int addressOffsetAlignment, const unsigned int valueIndex)
	{
		this->PageIndex = pageIndex;
		this->BaseAddress = baseAddress;
		this->AddressOffsetAlignment = addressOffsetAlignment;
		this->ValueStorageIndex = valueIndex;
		this->AddressCount = 0;
		this->ValueCount = 0;
		this->SizeInBytes = 0;
		this->BitsInternalAlloc = 0;
	};
};

#endif