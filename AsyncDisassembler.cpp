#include "AsyncDisassembler.h"
#include "BackendGlobalDef.h"

// Container of all currently UI visible lines of disassembly.
Vector<LONG_PTR> DisasmVisibleLines;

// Container of all executable memory pages in the target process.
Vector<MemoryRegion> mExecutablePagesList;

// Retrieves the correct page index in the list by passing an address inside it.
const int GetPageIndexFromAddress(const SIZE_T address)
{
	for (int i = 0; i < mExecutablePagesList.GetCount(); ++i)
	{
		const MemoryRegion& mem = mExecutablePagesList[i];
		if (address >= mem.BaseAddress && address < mem.BaseAddress + mem.MemorySize)
		{
			return i;
		}
	}
	
	return 0;
}

// Retrieves the correct page by passing an address inside it.
const MemoryRegion* GetPageFromAddress(const SIZE_T address)
{
	for (int i = 0; i < mExecutablePagesList.GetCount(); ++i)
	{
		const MemoryRegion* mem = &mExecutablePagesList[i];
		if (address >= mem->BaseAddress && address < mem->BaseAddress + mem->MemorySize)
		{
			return mem;
		}
	}
	
	return NULL;
}

AsyncDisassembler::AsyncDisassembler()
{
	this->mRunning = false;
}

AsyncDisassembler::~AsyncDisassembler()
{
	
}

// Gets whether the disassembler is running or not.
const bool AsyncDisassembler::IsRunning() const
{
	return this->mRunning;
}

// Refreshes the disassembly shown in the control view area, given the address to make it look for.
void AsyncDisassembler::RefreshDisasm(const SIZE_T addr, const SIZE_T size)
{
	// Start disassembly.
#ifdef _WIN64
	this->Disassemble(addr, size, mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, DisasmVisibleLines);
#else
	this->Disassemble(addr, size, ARCH_X86, DisasmVisibleLines);
#endif
}

void AsyncDisassembler::DoDisassembly(const SIZE_T address)
{
#ifdef _WIN64
	const MemoryRegion* const entrypointPage = GetPageFromAddress(address);
#else
	const MemoryRegion* const entrypointPage = GetPageFromAddress(address);
#endif

	if (entrypointPage)
	{
		// Entrypoint was found in one of the executable memory pages. Disassemble the page in case.
		this->RefreshDisasm(entrypointPage->BaseAddress, entrypointPage->MemorySize);
		
		// Signal the user interface that the asynchronous disassembly has finished.
		// This callback is executed from a seperate thread and therefore cannot be safely executed in the UI thread.
		this->DisasmCompleted(address);
	}
	else
	{
		// Entrypoint was not found in one of the memory pages. Maybe the user loaded a .NET executable.
		this->RefreshDisasm(mExecutablePagesList[0].BaseAddress, mExecutablePagesList[0].MemorySize);
		
		// Entrypoint was not found in one of the memory pages. Maybe the user loaded a .NET executable.
		this->DisasmCompleted(mExecutablePagesList[0].BaseAddress);
	}
}

// This method starts the asynchronous disassembly process.
void AsyncDisassembler::Start(const SIZE_T address)
{
	this->mRunning = true;
	
	// Signal the user interface that the disassembly has started asynchronous.
	// This callback does not run on a seperate thread and can be safely executed in the UI thread.
	this->DisasmStarted();
	
	// Start the asynchronous disassembly process.
	this->mWorker.Run(THISBACK1(DoDisassembly, address));
}

// Kills the disassembler if it is running in order to shut down operations on a possible crash detection.
void AsyncDisassembler::Kill()
{
	this->mRunning = false;
	
	// Block the thread until the disassembler thread has been killed.
	this->mWorker.Wait();
}

// Disassembles lineCount lines of assembly into MASM syntax OPCodes, starting from address.
// The output disassembly string is put at outInstructionString. Returns the length of the longest string bytes representation.
void AsyncDisassembler::Disassemble(const SIZE_T address, const SIZE_T size, const ArchitectureDefinitions architecture, Vector<LONG_PTR>& outInstructions)
{
	// Get rid of old set of instruction lines. After all, it is a refresh.
	outInstructions.Clear();
	
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