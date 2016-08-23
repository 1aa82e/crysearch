#include "AsyncDisassembler.h"
#include "BackendGlobalDef.h"

// Container of all currently UI visible lines of disassembly.
Vector<LONG_PTR> DisasmVisibleLines;

// Container of all executable memory pages in the target process.
Vector<DisasmMemoryRegion> mExecutablePagesList;

#define MINIMUM_MEMORY_SIZE	0x1000

// Retrieves the correct page index in the list by passing an address inside it.
const int GetPageIndexFromAddress(const SIZE_T address, SIZE_T* const sizePtr)
{
	for (int i = 0; i < mExecutablePagesList.GetCount(); ++i)
	{
		const DisasmMemoryRegion& mem = mExecutablePagesList[i];
		if (address >= mem.BaseAddress && address < mem.BaseAddress + mem.MemorySize)
		{
			if (sizePtr)
			{
				*sizePtr = mem.MemorySize;
			}
			return i;
		}
	}
	
	return 0;
}

// Retrieves the correct page by passing an address inside it.
const DisasmMemoryRegion* GetPageFromAddress(const SIZE_T address)
{
	for (auto& page : mExecutablePagesList)
	{
		// Loops until the memory region containing the specified address is found.
		const DisasmMemoryRegion* mem = &page;
		if (address >= mem->BaseAddress && address < mem->BaseAddress + mem->MemorySize)
		{
			return mem;
		}
	}
	
	// No containing memory page was found.
	return NULL;
}

// The AsyncDisassembler default constructor.
AsyncDisassembler::AsyncDisassembler()
{
	this->mRunning = false;
	this->mCurrentPageSize = 0;
}

// The AsyncDisassembler default destructor.
AsyncDisassembler::~AsyncDisassembler()
{
	// If a worker is still running, kill it first.
	this->Kill();
}

// Gets whether the disassembler is running or not.
const bool AsyncDisassembler::IsRunning() const
{
	return this->mRunning;
}

// Returns the size of the currently visible/disassembled page.
const LONG_PTR AsyncDisassembler::GetCurrentPageSize() const
{
	return this->mCurrentPageSize;
}

// Actually executes a part of the disassembly work.
void AsyncDisassembler::DoDisassembly(AsyncDisasmWorkerInformation* const pInformation)
{
	// Start disassembly.
#ifdef _WIN64
	this->Disassemble(pInformation->BaseAddress, pInformation->MemorySize, mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, pInformation->WorkerDisasmLines);
#else
	this->Disassemble(pInformation->BaseAddress, pInformation->MemorySize, ARCH_X86, pInformation->WorkerDisasmLines);
#endif

	// Indicate that this worker is done.
	pInformation->HasFinished = true;
}

// This method starts the asynchronous disassembly process.
void AsyncDisassembler::Start(const SIZE_T address)
{
	// Set the state to running.
	this->mRunning = true;
	
	// Save the address parameter for the user to retrieve it again later.
	this->mLastDisasmAddress = address;
	
	// Signal the user interface that the disassembly has started asynchronous.
	// This callback does not run on a seperate thread and can be safely executed in the UI thread.
	this->DisasmStarted();
	
	// Find the size of the memory region to be disassembled, so we can split the work.
#ifdef _WIN64
	const DisasmMemoryRegion* const pageInfo = GetPageFromAddress(address);
#else
	const DisasmMemoryRegion* const pageInfo = GetPageFromAddress(address);
#endif
	
	// In case this is the entrypoint disassembly phase, we need to check for NULL.
	const SIZE_T ba = pageInfo ? pageInfo->BaseAddress : mExecutablePagesList[0].BaseAddress;
	const SIZE_T bs = pageInfo ? pageInfo->MemorySize : mExecutablePagesList[0].MemorySize;
	
	// Set the page size for the user interface to peek.
	this->mCurrentPageSize = bs;

	// First, split the total memory size to disassemble into tCount blocks.
	const int tCount = mMemoryScanner->GetSystemThreadCount();
	const SIZE_T blockSize = bs / tCount;
	const unsigned int remainder = bs % tCount;
	
	// Create worker information structures accordingly.
	for (int t = 0; t < tCount; ++t)
	{
		// Create a worker information strucure and add it to the internal adminstration.
		this->mWorkerInformations << AsyncDisasmWorkerInformation(ba + (t * blockSize), blockSize, false);
	}
	
	// If there is a remainder in block size, we need to add this remainder to the last worker.
	if (remainder)
	{
		this->mWorkerInformations[tCount - 1].MemorySize += remainder;
	}
	
	// Start the asynchronous disassembly process over multiple threads.
	for (auto& info : this->mWorkerInformations)
	{
		this->mThreadPool & THISBACK1(DoDisassembly, &info);
	}
}

// Peeks whether the disassembly work has completed, i.e. all workers have finished their work.
const bool AsyncDisassembler::PeekIsFinished() const
{
	// Walk the currently running workers.
	for (auto const& info : this->mWorkerInformations)
	{
		// Check whether the current worker has completed.
		if (!info.HasFinished)
		{
			// A worker is not yet finished.
			return false;
		}
	}
	
	// All workers have completed their work.
	return true;
}

// Peeks the disassembler for completion and copies the worker output to centralized output.
const bool AsyncDisassembler::PeekAndCopy(SIZE_T* const pAddress)
{
	// Check whether the disassembler is finished.
	if (this->PeekIsFinished())
	{
		// Inform the user interface what the base address of the disassmbler was.
		*pAddress = this->mLastDisasmAddress;
		
		// It is finished, copy the seperate outputs to a single output.
		for (auto& info : this->mWorkerInformations)
		{
			DisasmVisibleLines.Append(info.WorkerDisasmLines);
			info.WorkerDisasmLines.Clear();
		}
		
		// Clear used resources.
		this->mWorkerInformations.Clear();
		this->mRunning = false;

		// Indicate that the disassembler is done.
		return true;
	}
	
	// Not yet finished.
	return false;
}

// Kills the disassembler if it is running in order to shut down operations on a possible crash detection.
void AsyncDisassembler::Kill()
{
	this->mRunning = false;
	
	// Block the thread until the disassembler threads has been killed.
	while (!this->PeekIsFinished())
	{
		Sleep(10);
	}
}

// Disassembles lineCount lines of assembly into MASM syntax OPCodes, starting from address.
// The output disassembly string is put at outInstructionString. Returns the length of the longest string bytes representation.
void AsyncDisassembler::Disassemble(const SIZE_T address, const SIZE_T size, const ArchitectureDefinitions architecture, Vector<LONG_PTR>& outInstructions)
{
	DISASM disasm;
	memset(&disasm, 0, sizeof(DISASM));
	
	// Query virtual pages inside target process.
    Byte* const buffer = new Byte[size];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, size, NULL);
    
    // Set EIP, correct architecture and security block to prevent access violations.
	disasm.EIP = (UIntPtr)buffer;
	disasm.Archi = architecture;
	disasm.VirtualAddr = (UInt64)address;

	const UInt64 codePageEnd = ((UInt64)buffer + size);

	// Disassembly each line encountered until the end of the buffer is reached.
	while (this->mRunning && disasm.EIP < codePageEnd)
	{
		const int len = CryDisasm(&disasm);
		if (len == OUT_OF_BLOCK)
		{
			break;
		}
		else if (len == UNKNOWN_OPCODE)
		{
			// An unknown instruction was encountered. Increment the counter to proceed disassembling until the end of the page is hit.
			outInstructions.Add((SIZE_T)disasm.VirtualAddr);

			// Increment disasm structure counters.
			++disasm.EIP;
			++disasm.VirtualAddr;
		}
		else
		{
			// Disassembled succesfully, add a new line.
			outInstructions.Add((SIZE_T)disasm.VirtualAddr);

			// Increment disasm structure counters.
			disasm.EIP += len;
			disasm.VirtualAddr += len;
		}
	}
	
	delete[] buffer;
}