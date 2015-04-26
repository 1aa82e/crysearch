#include "Disassembler.h"
#include "BackendGlobalDef.h"

// Stub functions are needed to avoid linker errors from multiple usage of the Disasm functions.
int __stdcall CryDisasm(LPDISASM lpDisasm)
{
	return Disasm(lpDisasm);
}

// ---------------------------------------------------------------------------------------------

// Retrieves the line of disassembly at the specified address. The return value is the string 
// representation of the disassembled line. A pointer to receive the bytes can be specified.
String DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob)
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

	int len = CryDisasm(&disasm);
	if (len > 0)
	{
		// Place the disassembled byte sequence in the output parameter if it was specified.
		if (outAob)
		{
			outAob->Allocate(len);
			memcpy(outAob->Data, (Byte*)disasm.EIP, len);
		}
		
		return disasm.CompleteInstr;
	}
	
	return "";
}

// Retrieves the previous line of disassembly reflected against the specified address. The address inputted must
// be the address of a valid instruction line. The instruction size parameter specifies how big the desired
// instruction must be to have a match. This greatly decreases the chance of a mismatch.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob)
{
	// Query the memory page this breakpoint occured in, so we can guarantee accurate instruction parsing.
	MEMORY_BASIC_INFORMATION block;
	SIZE_T outputVal;
	if (VirtualQueryEx(mMemoryScanner->GetHandle(), (void*)address, &block, sizeof(block)))
	{
		DISASM disasm;
		memset(&disasm, 0, sizeof(DISASM));
		
		Byte* buffer = new Byte[block.RegionSize];
		CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)block.BaseAddress, buffer, block.RegionSize, NULL);
		
		// Set EIP, correct architecture and security block to prevent access violations.
		disasm.EIP = (UIntPtr)buffer;
		disasm.Archi = architecture;
		disasm.VirtualAddr = (UInt64)block.BaseAddress;
	
		UInt64 codePageEnd = ((UInt64)buffer + block.RegionSize);
		
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
				if ((disasm.VirtualAddr + len) == address)
				{
					// This is the previous instruction, break the loop.
					outputVal = (SIZE_T)disasm.VirtualAddr;
					
					if (outAob)
					{
						outAob->Allocate(len);
						memcpy(outAob->Data, (Byte*)disasm.EIP, len);
					}
							
					break;
				}
				else
				{
					// Not yet the previous instruction.
					disasm.EIP += len;
					disasm.VirtualAddr += len;
				}
			}
		}
		
		delete[] buffer;	
	}
	
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
	     	if (((block.Protect & MEM_EXECUTABLE) != 0) || ((block.Protect & MEM_WRITABLE) != 0))
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