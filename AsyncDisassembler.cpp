#include "AsyncDisassembler.h"
#include "BackendGlobalDef.h"

// Container of all currently UI visible lines of disassembly.
Vector<LONG_PTR> DisasmVisibleLines;

// Container of all executable memory pages in the target process.
Vector<MemoryRegion> mExecutablePagesList;

#define MINIMUM_MEMORY_SIZE	0x1000

// Retrieves the correct page index in the list by passing an address inside it.
const int GetPageIndexFromAddress(const SIZE_T address, SIZE_T* const sizePtr)
{
	const int count = mExecutablePagesList.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const MemoryRegion& mem = mExecutablePagesList[i];
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
const MemoryRegion* GetPageFromAddress(const SIZE_T address)
{
	for (auto& page : mExecutablePagesList)
	{
		// Loops until the memory region containing the specified address is found.
		const MemoryRegion* mem = &page;
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
	this->Disassemble(pInformation->BaseAddress, pInformation->MemorySize, mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64, pInformation->WorkerDisasmLines);
#else
	this->Disassemble(pInformation->BaseAddress, pInformation->MemorySize, CS_MODE_32, pInformation->WorkerDisasmLines);
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
	const MemoryRegion* const pageInfo = GetPageFromAddress(address);
#else
	const MemoryRegion* const pageInfo = GetPageFromAddress(address);
#endif
	
	// In case this is the entrypoint disassembly phase, we need to check for NULL.
	const SIZE_T ba = pageInfo ? pageInfo->BaseAddress : mExecutablePagesList[0].BaseAddress;
	const SIZE_T bs = pageInfo ? pageInfo->MemorySize : mExecutablePagesList[0].MemorySize;
	
	// Set the page size for the user interface to peek.
	this->mCurrentPageSize = bs;

	// First, split the total memory size to disassemble into tCount blocks.
	const int tCount = 1;//mMemoryScanner->GetSystemThreadCount();
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
void AsyncDisassembler::Disassemble(const SIZE_T address, const SIZE_T size, const cs_mode architecture, Vector<LONG_PTR>& outInstructions)
{
	// Query virtual pages inside target process.
    Byte* const buffer = new Byte[size];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, size, NULL);
    
    // Reserve an approximated buffer for instruction lines.
    outInstructions.Reserve((int)size / 4);
	
	// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
	csh handle;
	cs_open(CS_ARCH_X86, architecture, &handle);
    
    // Allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
	cs_insn* insn = cs_malloc(handle);
	const Byte* bufIteratorPtr = buffer;
	size_t code_size = size;
	uint64 iterAddress = address;
	uint64 prevAddress = iterAddress;
	
	// Disassemble one instruction a time & store the result into @insn variable.
	while (cs_disasm_iter(handle, &bufIteratorPtr, &code_size, &iterAddress, insn))
	{
		// Disassembled succesfully, add a new line.
		outInstructions.Add((SIZE_T)prevAddress);
		prevAddress = iterAddress;
	}
	
	// Release the cache memory when done.
	cs_free(insn, 1);

	// Close the Capstone handle.
	cs_close(&handle);
		
	// Clean up used buffers and shrink instruction line buffer.
	outInstructions.Shrink();
	delete[] buffer;
}