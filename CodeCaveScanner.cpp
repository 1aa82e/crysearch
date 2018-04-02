#include "CodeCaveScanner.h"
#include "BackendGlobalDef.h"

// CodeCaveScanner default constructor.
CodeCaveScanner::CodeCaveScanner()
{
	this->mRunning = false;
}

// CodeCaveScanner default destructor.
CodeCaveScanner::~CodeCaveScanner()
{
	
}

// ---------------------------------------------------------------------------------------------

// Checks whether a specific address qualifies as a code cave.
const CodeCaveType CodeCaveScanner::QualifyForStartOfCodeCave(const cs_insn* insn) const
{
	cs_detail* detail = insn->detail;
	
	// Check for a zero instruction.
	if (insn->size == 2 && *(WORD*)insn->bytes == 0)
	{
		return ZERO_INSTRUCTIONS;
	}
	// Check for a NOP sled.
	else if (insn->id == X86_INS_NOP)
	{
		return NOP_SLED;
	}
	// Check for an INT3 sled.
	else if (insn->id == X86_INS_INT3)
	{
		return INT3_SLED;
	}
	
	return UNKNOWN;
}

// The private worker function that actually executes the scan logic.
void CodeCaveScanner::DoScanForCodeCaves(const SIZE_T base, const SIZE_T size, const int caveLength, const cs_mode arch)
{
	// Query virtual pages inside target process.
    Byte* const buffer = new Byte[size];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)base, buffer, size, NULL);
	
	// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
	csh handle;
	cs_open(CS_ARCH_X86, arch, &handle);
    
    // Allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
	cs_insn* insn = cs_malloc(handle);
	const Byte* bufIteratorPtr = buffer;
	size_t code_size = size;
	uint64 iterAddress = base;
	uint64 prevAddress = iterAddress;
	
	// Keeps track of the of code cave we started encountering.
	CodeCaveType cType = UNKNOWN;
	SIZE_T caveAddr = 0;
	int currentCaveSize = 0;
	
	// Keep disassembling until we reach the end of the specified input memory block.
	do
	{
		// Disassemble one instruction a time & store the result into @insn variable.
		while (cs_disasm_iter(handle, &bufIteratorPtr, &code_size, &iterAddress, insn))
		{
			// Disassembled succesfully, check whether this instruction would qualify as the
			// start or addition of a code cave.
			CodeCaveType tempType = this->QualifyForStartOfCodeCave(insn);
			if (tempType != UNKNOWN)
			{
				// Is the code cave starting?
				if (cType == UNKNOWN)
				{
					// Set address and start recording code cave size.
					caveAddr = (SIZE_T)prevAddress;
					currentCaveSize = insn->size;
				}
				else
				{
					// Increment the size of the code cave and continue.
					currentCaveSize += insn->size;
				}

				// Set the code cave type.
				cType = tempType;
			}
			else
			{
				// Check the size of the code cave, do we have a sufficiently large one?
				if (currentCaveSize >= caveLength)
				{
					// Report the code cave to the user.
					this->ScannerResultFound(caveAddr, currentCaveSize);
				}

				// Reset code cave data.
				caveAddr = 0;
				currentCaveSize = 0;
				cType = tempType;
			}
			
			prevAddress = iterAddress;
		}

		// Check if we encountered an address that Capstone could not disassemble.
		if (cs_errno(handle) == CS_ERR_OK && iterAddress < base + size)
		{
			// We don't want to check anything here, just increment the instruction pointer.
			prevAddress = ++iterAddress;
		}
	}
	while (prevAddress < base + size && this->mRunning);
	
	// Release the cache memory when done.
	cs_free(insn, 1);

	// Close the Capstone handle and clean up used buffer.
	cs_close(&handle);
	delete[] buffer;
	
	// Indicate that this work is done.
	this->mRunning = false;
	this->ScannerFinished();
}

// Scans for code caves asynchronously, given some memory block and cave size.
void CodeCaveScanner::ScanForCodeCaves(const SIZE_T base, const SIZE_T size, const int caveLength)
{
	// Set the state to running.
	this->mRunning = true;
	
	// Signal the user interface that the scanning has started asynchronous.
	// This callback does not run on a seperate thread and can be safely executed in the UI thread.
	this->ScannerStarted();
	
	// Start the scanning.
#ifdef _WIN64
	this->mDisasmThread.Start(THISBACK4(DoScanForCodeCaves, base, size, caveLength, mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64));
#else
	this->mDisasmThread.Start(THISBACK4(DoScanForCodeCaves, base, size, caveLength, CS_MODE_32));
#endif
}

// ---------------------------------------------------------------------------------------------

// Gets whether the code cave scanner is running or not.
const bool CodeCaveScanner::IsRunning() const
{
	return this->mRunning;
}

// Kills the code cave scanner if it is running in order to shut down operations on a possible crash detection.
void CodeCaveScanner::Kill()
{
	this->mRunning = false;
	
	// Block the thread until the disassembler threads has been killed.
	this->mDisasmThread.Wait();
}