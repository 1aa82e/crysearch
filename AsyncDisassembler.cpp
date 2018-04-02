#include "AsyncDisassembler.h"
#include "BackendGlobalDef.h"

// Container of all currently UI visible lines of disassembly.
Vector<LONG_PTR> DisasmVisibleLines;

#define MINIMUM_MEMORY_SIZE	0x1000

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

// This method starts the asynchronous disassembly process.
void AsyncDisassembler::Start(const SIZE_T address, const MemoryRegion& curRegion)
{
	// Set the state to running.
	this->mRunning = true;
	
	// Save the address parameter for the user to retrieve it again later.
	this->mLastDisasmAddress = address;
	
	// Signal the user interface that the disassembly has started asynchronous.
	// This callback does not run on a seperate thread and can be safely executed in the UI thread.
	this->DisasmStarted();
	
	// Find the size of the memory region to be disassembled, so we can split the work.
	MemoryRegion containingPage;
	containingPage.BaseAddress = 0;
	containingPage.MemorySize = 0;
	GetMemoryPageByAddress(address, containingPage, NULL);
	
	// In case this is the entrypoint disassembly phase, we need to check for NULL.
	const SIZE_T ba = containingPage.BaseAddress ? containingPage.BaseAddress : curRegion.BaseAddress;
	const SIZE_T bs = containingPage.MemorySize ? containingPage.MemorySize : curRegion.MemorySize;
	
	// Set the current page size.
	this->mCurrentPageSize = bs;

	// Start disassembly.
#ifdef _WIN64
	this->mDisasmThread.Start(THISBACK3(Disassemble, ba, bs, mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64));
#else
	this->mDisasmThread.Start(THISBACK3(Disassemble, ba, bs, CS_MODE_32));
#endif
}

// Peeks whether the disassembly work has completed.
const bool AsyncDisassembler::PeekIsFinished(SIZE_T* const pAddress)
{
	// Check whether the disassembler is finished.
	if (!this->mRunning)
	{
		// Inform the user interface what the base address of the disassmbler was.
		*pAddress = this->mLastDisasmAddress;		
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
	this->mDisasmThread.Wait();
}

// Disassembles lineCount lines of assembly into MASM syntax OPCodes, starting from address.
// The output disassembly string is put at outInstructionString. Returns the length of the longest string bytes representation.
void AsyncDisassembler::Disassemble(const SIZE_T address, const SIZE_T size, const cs_mode architecture)
{
	// Disassemble the given region.
	DisassembleRegion(address, size, architecture, DisasmVisibleLines, this->mRunning);
	
	// Indicate that this work is done.
	this->mRunning = false;
}