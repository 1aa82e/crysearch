#include "PointerScanner.h"

// PointerScanner default constructor.
PointerScanner::PointerScanner()
{
	this->killSwitch = false;
	this->readSize = mMemoryScanner->IsX86Process() ? sizeof(int) : sizeof(__int64);
}

// PointerScanner default destructor.
PointerScanner::~PointerScanner() noexcept(true)
{
	
}

// ---------------------------------------------------------------------------------------------

// Scans a static address for a match in the pointer scan.
const bool PointerScanner::ScanStaticAddress(const SIZE_T staticAddr, const SIZE_T pAddress, unsigned int* pRecursionLevel, Vector<SIZE_T>& pOffsets) const
{
	// Try to read from the base-address.
	SIZE_T localBuf = 0;
	if (mMemoryScanner->Peek(staticAddr, this->readSize, &localBuf))
	{
		// Check if the value matches.
		if (localBuf == pAddress)
		{
			pOffsets.Add(0);
			return true;
		}
		else
		{
			// The base-address did not match. Now try all offsets in the specified bounds.
			// We now only try aligned addresses.
			for (unsigned int offset = this->readSize; offset < this->maxoffset; offset += this->readSize) // only aligned scans?
			{
				// Try to read from the base-address + offset.
				if (mMemoryScanner->Peek(staticAddr + offset, this->readSize, &localBuf))
				{
					// Check if the value matches.
					if (localBuf == pAddress)
					{
						pOffsets.Add(offset);
						return true;
					}
					else
					{
						// Direct offset matching did not provide any results. We now check whether
						// the base-address + offset is a valid pointer. If so, we recurse one
						// level down and try again, until we reach the maximum recursion level.
						if (mModuleManager->GetModuleFromContainedAddress(localBuf) && *pRecursionLevel <= this->maxrec)
						{
							++(*pRecursionLevel);
							return this->ScanStaticAddress(localBuf, pAddress, pRecursionLevel, pOffsets);
						}
					}
				}
			}
		}
	}
	
	// We did not find anything for this address.
	return false;
}

// Adds a pointer scan result to the global store.
void PointerScanner::AddPointerScanResult(const SIZE_T base, const Vector<SIZE_T>& offsets)
{
	// Enter the critical section to allow only one thread to add its results.
	this->mScanResultsCS.Enter();
	
	// Create a pointer scan result and store it.
	PointerScanResult& p = PointerScanResults.Add();
	p.BaseAddress = base;
	p.PointerOffsets.Append(offsets);
	
	// Leave the critical section.
	this->mScanResultsCS.Leave();
}

// Processes a memory page from the target process.
void PointerScanner::ProcessMemoryPage(const MemoryRegion& reg, const SIZE_T pAddress)
{
	Vector<SIZE_T> constants;
	
	// Disassemble the memory page and retrieve all constants inside the instructions.
	DisassembleGetConstantAddresses(reg.BaseAddress, reg.MemorySize, mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64, constants, this->killSwitch);
	
	// Walk the constants we received, to filter out those that point somewhere inside the
	// process. We only want potential pointers.
	unsigned int numAddresses = 0;
	Vector<SIZE_T> queued;
	const int count = constants.GetCount();
	for (int i = 0; i < count && this->killSwitch; ++i)
	{
		// Is the address inside a module? (Static address that qualifies as pointer).
		if (mModuleManager->GetModuleFromContainedAddress(constants[i]))
		{
			queued.Add(constants[i]);
			++numAddresses;
		}
	}
	
	// Delete the memory buffer for the constants.
	constants.Clear();
	constants.Shrink();
	
	// Start the actual scanning process. We first check whether the static addresses we have
	// point to the address we specified. If not, we try all offsets and recurse our way down
	// until we reached the maximum recursion level.
	const int offsetcount = queued.GetCount();
	for (int o = 0; o < offsetcount && this->killSwitch; ++o)
	{
		// Start the actual scanning for this static address.
		unsigned int recursionLevel = 1;
		Vector<SIZE_T> returnOffsets;
		if (this->ScanStaticAddress(queued[o], pAddress, &recursionLevel, returnOffsets))
		{
			// We found a match, possibly by recursion.
			this->AddPointerScanResult(queued[o], returnOffsets);
		}
	}
	
	// Set the completion for this memory page, and check whether the kill switch should be reset.
	this->mCompletionCS.Enter();
	if (--this->completionCount <= 0)
	{
		this->killSwitch = false;
	}
	this->mCompletionCS.Leave();
}

// Starts a new pointer scan.
void PointerScanner::StartPointerScan(const SIZE_T pAddress, const SIZE_T pMaxOff, const SIZE_T pMaxRec)
{
	this->maxoffset = pMaxOff;
	this->maxrec = pMaxRec;
	
	// Set the kill switch variable to running.
	this->killSwitch = true;
	
	// Retrieve all memory pages in the target process.
	Vector<MemoryRegion> pages;
	GetExecutableMemoryPagesList(pages);
	
	// Clear old results if applicable.
	PointerScanResults.Clear();
	
	// Create threadpool to dispatch disassembling work in parallel.
	this->completionCount = pages.GetCount();
	for (const MemoryRegion& page : pages)
	{
		this->dispar & THISBACK2(ProcessMemoryPage, page, pAddress);
	}
}

// Polls whether the pointer scan has finished.
const bool PointerScanner::PollPointerScanCompleted() const
{
	return this->completionCount <= 0;
}

// Sets the killswitch, killing the pointer scanner whenever possible.
void PointerScanner::Kill()
{
	// Set the killswitch.
	this->killSwitch = false;
	
	// Wait for all workers to finish.
	this->dispar.Finish();
}