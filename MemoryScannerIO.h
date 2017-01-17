#ifndef _CrySearch_MemoryScannerIO_h_
#define _CrySearch_MemoryScannerIO_h_

// Represents a disk storage structure header for the memory scanner.
struct MemoryRegionFileHeader
{
	// Internal variables to restore a Bits structure for U++. Do not use or spoil these.
	dword _buf;
	int _alloc;
	
	// Identifies the page in CrySearch memory.
	unsigned int PageIndex;
	
	// Identifies the base address of the page.
	SIZE_T BaseAddress;
	
	// Indicates the distance in bytes between addresses in the storage block.
	unsigned int AddressOffset;
	
	// Indicates the size of this storage block on the disk including the header size. This
	// size can be at most the maximum configured blocksize. If the storage block exceeds
	// that size, a new block will have its base address start at the remaining storage.
	SIZE_T SizeInBytes;
	
	// Represents the start of the actual storage bitset.
	DWORD StorageStart;
};

#endif