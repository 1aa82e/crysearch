#ifndef _CrySearch_MemoryScannerContext_h_
#define _CrySearch_MemoryScannerContext_h_

#include <Core/Core.h>

using namespace Upp;

#include "MemoryScannerIO.h"

// Represents a memory region found by the memory scanner.
struct MemoryRegion : Moveable<MemoryRegion>
{
	// Represents the base address of the memory region.
	SIZE_T BaseAddress;
	
	// Represents the size of the memory region.
	SIZE_T MemorySize;
};

// Defines a set of parameters needed for a new scan.
struct WorkerRegionParameterData
{
	// Indicates where the worker input starts in the memory page vector.
	unsigned int OriginalStartIndex;
	
	// Indicates how long the input in the memory page vector is for this worker.
	unsigned int Length;
	
	// Default constructor, initializing all variables to defaults.
	WorkerRegionParameterData()
	{
		this->OriginalStartIndex = 0;
		this->Length = 0;
	};
};

// Defines the maximum size of a buffer allocated by the memory scanner that triggers a reduced 
// reallocation. The second definition is the reduced reallocation factor.
// NOTE: This number is the size in elements! Not the size in BYTES!!!
#define MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD		0x400000 // 16 MB, assumed that element size is 4 bytes.

// Defines the context structure for a memory scanner worker.
struct MemoryScannerWorkerContext : Moveable<MemoryScannerWorkerContext>
{
	// Identifies the worker.
	int WorkerIdentifier;

	// Worker-wide variable that indicates whether it has completed.
	bool FinishedWork;

	// The scan parameters.
	WorkerRegionParameterData RegionData;
	
	// The size of the biggest memory region that this worker is going to process. By keeping
	// track of this number, we only have to allocate a buffer once for the whole worker.
	SIZE_T MaximumMemoryRegionBufferSize;
	
	// The buffer in which memory pages can be loaded during the scanning phase.
	Byte* MemoryRegionBuffer;
	
	// The alignment size for the scan phase.
	int FastScanAlignSize;
	
	// The addresses output file stream.
	FileOut OutAddressesFile;
	
	// The values output file stream.
	FileOut OutValuesFile;
	
	// The file header for this worker's output addresses file.
	StorageFileHeader OutAddressesFileHeader;
	
	// The worker results buffer for addresses, which has a fixed size on the heap.
	Bits LocalAddressesBuffer;
	
	// The worker results buffer for values, which has a fixed size on the heap.
	// However, because of the templating, this buffer is initialized outside the context.
	void* LocalValuesBuffer;
	
	// The file header of the previously written addresses file (for next scans).
	StorageFileHeader InOldFileHeader;
	
	// Contains the path to the input file of addresses (for next scans).
	String InOldAddressesFilePath;
	
	// The input file stream for next scan workers, reading the previously written addresses file.
	FileIn InOldAddressesFile;
	
	// Contains the path to the input file of values (for next scans).
	String InOldValuesFilePath;
	
	// The input file stream for next scan workers, reading the previously written values file.
	FileIn InOldValuesFile;
	
	// The current value index in the output file for a worker.
	unsigned int OutputValueFileIndex;
	
	// Indicates how many bytes were read from the memory page that is currently being scanned.
	SIZE_T MemoryRegionBytesRead;
	
	// A pointer to the output file header for the current memory page and current block.
	MemoryRegionFileHeader* OutputFileStoragePtr;
	
	// A pointer to the input file header for the current block in next scan.
	MemoryRegionFileHeader* InputOldFileStoragePtr;
	
	// A bitset structure containing the input data for the current block in next scan.
	Bits InputOldFileAddressesBuffer;
	
	// A buffer for old input values. The declaration is not typed, because the buffer is
	// initialized outside of the typed context.
	void* InputOldFileValuesBuffer;
	
	// -----------------------------------------------------------------------------------------
	
	// Default constructor.
	MemoryScannerWorkerContext()
	{
		this->WorkerIdentifier = 0;
		this->FinishedWork = false;
		this->MaximumMemoryRegionBufferSize = 0;
		this->FastScanAlignSize = 0;
		this->MemoryRegionBuffer = NULL;
		this->LocalValuesBuffer = NULL;
		this->OutputValueFileIndex = 0;
		this->MemoryRegionBytesRead = 0;
		this->OutputFileStoragePtr = NULL;
		this->InputOldFileStoragePtr = NULL;
		this->InputOldFileValuesBuffer = NULL;
	};
	
	// Allocates local address buffer for a worker.
	void AllocateLocalAddressBuffer()
	{
		this->LocalAddressesBuffer.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	};

	// Releases local buffers for a worker.
	void ReleaseLocalBuffers()
	{
		// Delete local addresses buffer.
		this->LocalAddressesBuffer.Clear();
		
		// Delete local values buffer.
		if (this->LocalValuesBuffer)
		{
			delete[] this->LocalValuesBuffer;
			this->LocalValuesBuffer = NULL;
		}
		
		// Delete buffer for memory region copies.
		if (this->MemoryRegionBuffer)
		{
			delete[] this->MemoryRegionBuffer;
			this->MemoryRegionBuffer = NULL;
		}
	};
	
	// (Re)Opens the addresses file handle for the next scan worker.
	void OpenAddresses(const String& addrFile)
	{
		this->OutAddressesFile.Open(addrFile);
	};
	
	// (Re)Opens the values file handle for the next scan worker.
	void OpenValues(const String& valFile)
	{
		this->OutValuesFile.Open(valFile);
	};
	
	// (Re)Opens the input addresses file handle for the next scan worker.
	void OpenInputAddresses(const String& addrFile)
	{
		this->InOldAddressesFilePath = addrFile;
		this->InOldAddressesFile.Open(addrFile);
	};
	
	// (Re)Opens the input values file handle for the next scan worker.
	void OpenInputValues(const String& valFile)
	{
		this->InOldValuesFilePath = valFile;
		this->InOldValuesFile.Open(valFile);
	};
	
	// Closes file handles for this worker.
	void ReleaseFiles()
	{
		this->OutAddressesFile.Close();
		this->OutValuesFile.Close();
		this->InOldAddressesFile.Close();
		this->InOldValuesFile.Close();
	};
};

#endif