#include "Disassembler.h"
#include "BackendGlobalDef.h"

// Stub functions are needed to avoid linker errors from multiple usage of the Disasm functions.
int __stdcall CryDisasm(LPDISASM lpDisasm)
{
	return Disasm(lpDisasm);
}

// ---------------------------------------------------------------------------------------------

// Retrieves the line of disassembly at the specified address.
DisasmLine DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture)
{
	const DWORD bufferLength = architecture == ARCH_X64 ? 20 : 16;
	DISASM disasm;
	memset(&disasm, 0, sizeof(DISASM));
	
	// Query virtual pages inside target process.
    Byte* const buffer = new Byte[bufferLength];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
    
    // Set EIP, correct architecture and security block to prevent access violations.
	disasm.EIP = (UIntPtr)buffer;
	disasm.Archi = architecture;
	disasm.VirtualAddr = (UInt64)address;

	const UInt64 codePageEnd = ((UInt64)buffer + bufferLength);
	
#ifdef _WIN64
	disasm.SecurityBlock = (UInt32)(codePageEnd - disasm.EIP);
#else
	disasm.SecurityBlock = (UIntPtr)(codePageEnd - disasm.EIP);
#endif

	DisasmLine outputVal;
	int len = CryDisasm(&disasm);
	if (len > 0)
	{
#ifdef _WIN64
		outputVal.VirtualAddress = disasm.VirtualAddr;
#else
		outputVal.VirtualAddress = (int)disasm.VirtualAddr;
#endif
	
		outputVal.BytesStringRepresentation.Allocate(len);
		memcpy(outputVal.BytesStringRepresentation.Data, (Byte*)disasm.EIP, len);
		outputVal.InstructionLine = disasm.CompleteInstr;
	}
	
	return outputVal;
}

// Retrieves the previous line of disassembly reflected against the specified address. The address inputted must
// be the address of a valid instruction line.
DisasmLine DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture)
{
	DisasmLine outputVal;
	const DWORD bufferLength = architecture == ARCH_X64 ? 20 : 16;
	SIZE_T newAddr = address - bufferLength;
	
	DISASM disasm;
	memset(&disasm, 0, sizeof(DISASM));
	
	// Query virtual pages inside target process.
    Byte* buffer = new Byte[bufferLength];
	const Byte* const staticBufferPtr = buffer;
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)newAddr, buffer, bufferLength, NULL);
    
    // Set EIP, correct architecture and security block to prevent access violations.
	disasm.EIP = (UIntPtr)buffer;
	disasm.Archi = architecture;
	disasm.VirtualAddr = (UInt64)newAddr;

	UInt64 codePageEnd = ((UInt64)buffer + bufferLength);
	
#ifdef _WIN64
	disasm.SecurityBlock = (UInt32)(codePageEnd - disasm.EIP);
#else
	disasm.SecurityBlock = (UIntPtr)(codePageEnd - disasm.EIP);
#endif

	while (disasm.VirtualAddr < address)
	{
		const int len = CryDisasm(&disasm);
		if (len == OUT_OF_BLOCK)
		{
			break;
		}
		else if (len == UNKNOWN_OPCODE)
		{
			++disasm.EIP;
			++disasm.VirtualAddr;
		}
		else
		{
			if ((disasm.VirtualAddr + len) != address)
			{
				// This is not the previous instruction, add the length to EIP and proceed.
				disasm.EIP += len;
				disasm.VirtualAddr += len;
			}
			else
			{
				// This is the previous instruction.
#ifdef _WIN64
				outputVal.VirtualAddress = disasm.VirtualAddr;
#else
				outputVal.VirtualAddress = (int)disasm.VirtualAddr;
#endif
			
				outputVal.BytesStringRepresentation.Allocate(len);
				memcpy(outputVal.BytesStringRepresentation.Data, (Byte*)disasm.EIP, len);
				outputVal.InstructionLine = disasm.CompleteInstr;
				break;
			}
		}

		// No suitable instruction was found. This means obfuscated code may have been found. Retry the lookup with other indexes.
		if (disasm.VirtualAddr >= address && !outputVal.VirtualAddress)
		{
			disasm.VirtualAddr = (UInt64)++newAddr;
			disasm.EIP = (UIntPtr)++buffer;
#ifdef _WIN64
			disasm.SecurityBlock = (UInt32)(--codePageEnd - disasm.EIP);
#else
			disasm.SecurityBlock = (UIntPtr)(--codePageEnd - disasm.EIP);
#endif
		}
	}
	
	delete[] staticBufferPtr;
	return outputVal;
}

// Retrieves all executable pages in the target process and puts them in the vector passed as parameter.
void RefreshExecutablePages(Vector<MemoryRegion>& pages)
{
	// Clear list first.
	pages.Clear();
	
	SIZE_T incAddress = 0;
	MEMORY_BASIC_INFORMATION block;
	
	// Query virtual pages inside target process.
	while (VirtualQueryEx(mMemoryScanner->GetHandle(), (void*)incAddress, &block, sizeof(block)))
	{
		// Check whether region is readable and exclude scan types that are not wanted.
		if ((block.State == MEM_COMMIT) && (!(block.Protect & PAGE_GUARD)) && (!(block.Protect & PAGE_NOACCESS)))
	    {
	        // Only save pages that contain executable code.
	     	if (((block.Protect & MEM_EXECUTABLE) != 0))
	     	{
	     		// Memory region is valid for scanning, add it to the region list.
		        MemoryRegion memReg;
		        memReg.BaseAddress = (SIZE_T)block.BaseAddress;
			    memReg.MemorySize = block.RegionSize;
			    pages << memReg;
	     	}
	    }
	
		const SIZE_T oldIncAddress = incAddress;
	    incAddress = (SIZE_T)block.BaseAddress + block.RegionSize;
	    
	    // Compatibility issue between wow64 and x64 processes on some systems causes infinite loop.
		if (oldIncAddress > (SIZE_T)block.BaseAddress)
		{
			break;
		}
	}
}