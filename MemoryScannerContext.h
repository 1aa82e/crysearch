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
	
	// The alignment size for the scan phase.
	int FastScanAlignSize;
	
	// The addresses output file stream.
	FileOut OutAddressesFile;
	
	// The values output file stream.
	FileOut OutValuesFile;
	
	// The file header for this worker's output addresses file.
	StorageFileHeader OutAddressesFileHeader;
	
	// The worker results buffer for addresses, which has a fixed size on the heap.
	bool* LocalAddressesBuffer;
	
	// The file header of the previously written addresses file (for next scans).
	StorageFileHeader InOldFileHeader;
	
	// Contains the path to the input file of addresses (for next scans).
	String InOldAddressesFilePath;
	
	// The input file stream for next scan workers, reading the previously written addresses file.
	FileIn InOldAddressesFile;
	
	// Default constructor.
	MemoryScannerWorkerContext()
	{
		this->WorkerIdentifier = 0;
		this->FinishedWork = false;
		this->FastScanAlignSize = 0;
	};
	
	// Allocates local address buffer for a worker.
	void AllocateLocalAddressBuffer()
	{
		this->LocalAddressesBuffer = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	};
	
	// Releases local address buffer for a worker.
	void ReleaseLocalAddressBuffer()
	{
		delete[] this->LocalAddressesBuffer;
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
	
	// Closes file handles for this worker.
	void ReleaseFiles()
	{
		this->OutAddressesFile.Close();
		this->OutValuesFile.Close();
		this->InOldAddressesFile.Close();
	};
};

#endif