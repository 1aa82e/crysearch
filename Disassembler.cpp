#include "Disassembler.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"

// Stub functions are needed to avoid linker errors from multiple usage of the Disasm functions.
const int __stdcall CryDisasm(LPDISASM lpDisasm)
{
	return Disasm(lpDisasm);
}

// ---------------------------------------------------------------------------------------------

#define BYTE_INDEX_NOT_FOUND	0xFFFFFFFF

// Retrieves the line of disassembly at the specified address. The return value is the string
// representation of the disassembled line. A pointer to receive the bytes can be specified.
String DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob)
{
	const DWORD bufferLength = architecture == ARCH_X64 ? 20 : 16;
	DISASM disasm;
	memset(&disasm, 0, sizeof(DISASM));
	
	// Query virtual pages inside target process.
    Byte buffer[20];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
    
    // Set EIP, correct architecture and security block to prevent access violations.
	disasm.EIP = (UIntPtr)buffer;
	disasm.Archi = architecture;
	disasm.VirtualAddr = (UInt64)address;

	const UInt64 codePageEnd = ((UInt64)buffer + bufferLength);
	
#ifdef _WIN64
	disasm.SecurityBlock = (UInt32)(bufferLength);
#else
	disasm.SecurityBlock = (UIntPtr)(bufferLength);
#endif

	int len = CryDisasm(&disasm);
	if (len == UNKNOWN_OPCODE)
	{
		const Byte value = buffer[0];

		// Even if the instruction was not recognized, place the byte into the output array if it was specified.
		if (outAob)
		{
			outAob->Allocate(sizeof(Byte));
			*outAob->Data = value;
		}

		// Just return a 'defined byte' description to identify an unknown instruction.
		return "db " + FormatHexadecimalIntSpecial(value);
	}
	else if (len > 0)
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

template <typename T>
const unsigned int FindValueInBytes(const Byte* const bytes, const unsigned int length, const T value)
{
	// Walk the sequence of bytes.
	for (unsigned int i = 0; i < length; ++i)
	{
		// Compare using type-based comparison.
		if (*(T*)(bytes + i) == value)
		{
			return i;
		}
	}
	
	// Nothing was found!
	return BYTE_INDEX_NOT_FOUND;
}

const unsigned int FindValueInBytes(const Byte* const bytes, const unsigned int length, const Byte* const value, const unsigned int valueLength)
{
	// Walk the sequence of bytes.
	for (unsigned int i = 0; i < length; ++i)
	{
		// Compare memory using the input value size.
		if (memcmp(bytes + i, value, valueLength) == 0)
		{
			return i;
		}
	}
	
	// Nothing was found!
	return BYTE_INDEX_NOT_FOUND;
}

// Retrieves only the instruction bytes at the specified address. It's wise to input an array of 8 in size for the 'optOutMasking' parameter.
void DisasmForBytes(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob, Vector<char>* const optOutMasking)
{
	const DWORD bufferLength = architecture == ARCH_X64 ? 20 : 16;
	DISASM disasm;
	memset(&disasm, 0, sizeof(DISASM));
	
	// Query virtual pages inside target process.
    Byte buffer[20];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
    
    // Set EIP, correct architecture and security block to prevent access violations.
	disasm.EIP = (UIntPtr)buffer;
	disasm.Archi = architecture;
	disasm.VirtualAddr = (UInt64)address;

	const UInt64 codePageEnd = ((UInt64)buffer + bufferLength);
	
#ifdef _WIN64
	disasm.SecurityBlock = (UInt32)(bufferLength);
#else
	disasm.SecurityBlock = (UIntPtr)(bufferLength);
#endif

	int len = CryDisasm(&disasm);
	if (len == UNKNOWN_OPCODE)
	{
		const Byte value = buffer[0];

		// Even if the instruction was not recognized, place the byte into the output array if it was specified.
		if (outAob)
		{
			outAob->Allocate(sizeof(Byte));
			*outAob->Data = value;
		}
	}
	else if (len > 0)
	{
		// Place the disassembled byte sequence in the output parameter if it was specified.
		if (outAob)
		{
			outAob->Allocate(len);
			memcpy(outAob->Data, (Byte*)disasm.EIP, len);
		}
		
		// If the caller requested masking information, let's output it.
		if (optOutMasking)
		{
			// First fill the output with x's. Further on, some may be replaced by ?'s.
			optOutMasking->Set(0, 'x', len);
			
			// Let's find constants and their sizes and output them.
			if (disasm.Instruction.AddrValue)
			{
				// Check whether the AddrValue can be found in the instruction bytes.
				unsigned int index;
				const unsigned int dataSize = architecture == ARCH_X64 ? sizeof(DWORD64) : sizeof(DWORD);
				if (dataSize == sizeof(DWORD64))
				{
					index = FindValueInBytes((Byte*)disasm.EIP, len, disasm.Instruction.AddrValue);
				}
				else
				{
					index = FindValueInBytes((Byte*)disasm.EIP, len, (DWORD)disasm.Instruction.AddrValue);
				}
				
				// Did we find the value in the instruction bytes?
				if (index != BYTE_INDEX_NOT_FOUND)
				{
					optOutMasking->Set(index, '?', dataSize);
				}
			}
			if (disasm.Instruction.Immediat)
			{
				// Check whether the Immediat value can be found in the instruction bytes.
				unsigned int index;
				const unsigned int dataSize = architecture == ARCH_X64 ? sizeof(DWORD64) : sizeof(DWORD);
				if (dataSize == sizeof(DWORD64))
				{
					index = FindValueInBytes((Byte*)disasm.EIP, len, disasm.Instruction.AddrValue);
				}
				else
				{
					index = FindValueInBytes((Byte*)disasm.EIP, len, (DWORD)disasm.Instruction.AddrValue);
				}
				
				// Did we find the value in the instruction bytes?
				if (index != BYTE_INDEX_NOT_FOUND)
				{
					optOutMasking->Set(index, '?', dataSize);
				}
			}
			if (disasm.Argument1.Memory.Displacement)
			{
				// Check whether the first argument value can be found in the instruction bytes.
				const unsigned int dataSize = disasm.Argument1.ArgSize / 8;
				const unsigned int index = FindValueInBytes((Byte*)disasm.EIP, len, (Byte*)&disasm.Argument1.Memory.Displacement, dataSize);
				if (index != BYTE_INDEX_NOT_FOUND)
				{
					optOutMasking->Set(index, '?', dataSize);
				}
			}
			if (disasm.Argument2.Memory.Displacement)
			{
				// Check whether the second argument value can be found in the instruction bytes.
				const unsigned int dataSize = disasm.Argument2.ArgSize / 8;
				const unsigned int index = FindValueInBytes((Byte*)disasm.EIP, len, (Byte*)&disasm.Argument2.Memory.Displacement, dataSize);
				if (index != BYTE_INDEX_NOT_FOUND)
				{
					optOutMasking->Set(index, '?', dataSize);
				}
			}
			if (disasm.Argument3.Memory.Displacement)
			{
				// Check whether the third argument value can be found in the instruction bytes.
				const unsigned int dataSize = disasm.Argument3.ArgSize / 8;
				const unsigned int index = FindValueInBytes((Byte*)disasm.EIP, len, (Byte*)&disasm.Argument3.Memory.Displacement, dataSize);
				if (index != BYTE_INDEX_NOT_FOUND)
				{
					optOutMasking->Set(index, '?', dataSize);
				}
			}
		}
	}
}

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob)
{
	const DWORD bufferLength = architecture == ARCH_X64 ? 20 : 16;
	DISASM disasm;
	memset(&disasm, 0, sizeof(DISASM));
	
	// We make the buffer twice as large in this function, because we possibly need to disassemble a thunk too.
    Byte buffer[20 * 2];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
    
    // Set EIP, correct architecture and security block to prevent access violations.
	disasm.EIP = (UIntPtr)buffer;
	disasm.Archi = architecture;
	disasm.VirtualAddr = (UInt64)address;

	const UInt64 codePageEnd = ((UInt64)buffer + bufferLength);
	
#ifdef _WIN64
	disasm.SecurityBlock = (UInt32)(bufferLength);
#else
	disasm.SecurityBlock = (UIntPtr)(bufferLength);
#endif

	int len = CryDisasm(&disasm);
	if (len == UNKNOWN_OPCODE)
	{
		const Byte value = buffer[0];

		// Even if the instruction was not recognized, place the byte into the output array if it was specified.
		if (outAob)
		{
			outAob->Allocate(sizeof(Byte));
			*outAob->Data = value;
		}

		// Just return a 'defined byte' description to identify an unknown instruction.
		return "db " + FormatHexadecimalIntSpecial(value);
	}
	else if (len > 0)
	{
		// Place the disassembled byte sequence in the output parameter if it was specified.
		if (outAob)
		{
			outAob->Allocate(len);
			memcpy(outAob->Data, (Byte*)disasm.EIP, len);
		}
		
		StringBuffer outBuf(MAX_PATH + sizeof(disasm.CompleteInstr));
		String functionName;

		// If the address value of this instruction contains something, it may refer to a function in the import address table.
		if (disasm.Instruction.BranchType == CallType)
		{
			// Does the displacement value of the call argument refer to a thunk?
			if ((disasm.Argument1.Memory.Displacement && LoadedProcessPEInformation.FindImportedFunctionAddress((SIZE_T)disasm.Argument1.Memory.Displacement, functionName))
				|| (disasm.Instruction.AddrValue && LoadedProcessPEInformation.FindImportedFunctionAddress((SIZE_T)disasm.Instruction.AddrValue, functionName)))
			{
				// The instruction refers to an imported function.
				const unsigned int mnemonicLength = (unsigned int)strlen(disasm.Instruction.Mnemonic);
				char* outIterator = outBuf.Begin();
				memcpy(outIterator, disasm.Instruction.Mnemonic, mnemonicLength);
				outIterator += mnemonicLength;
				const unsigned int nameLen = functionName.GetLength();
				memcpy(outIterator, functionName, nameLen);
				outIterator += nameLen;
				*outIterator = 0x0;

				// Clean up and return the instruction string.
				outBuf.Strlen();
				return outBuf;
			}
			else
			{
				// Disassemble the instruction at the argument address to find out whether it actually is a thunk.
				CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)disasm.Instruction.AddrValue, buffer + bufferLength, bufferLength, NULL);
				DISASM thunk;
				thunk.EIP = (UIntPtr)buffer + bufferLength;
				thunk.Archi = architecture;
				thunk.VirtualAddr = (UInt64)disasm.Instruction.AddrValue;
				len = CryDisasm(&thunk);

				// Is the instruction actually an unconditional jump? If so, match the address to thunk addresses in the import table.
				if (thunk.Instruction.BranchType == JmpType)
				{
					if (LoadedProcessPEInformation.FindImportedFunctionAddress((SIZE_T)thunk.Argument1.Memory.Displacement, functionName))
					{
						// The instruction refers to an imported function.
						const unsigned int mnemonicLength = (unsigned int)strlen(disasm.Instruction.Mnemonic);
						char* outIterator = outBuf.Begin();
						memcpy(outIterator, disasm.Instruction.Mnemonic, mnemonicLength);
						outIterator += mnemonicLength;
						const unsigned int nameLen = functionName.GetLength();
						memcpy(outIterator, functionName, nameLen);
						outIterator += nameLen;
						*outIterator = 0x0;

						// Clean up and return the instruction string.
						outBuf.Strlen();
						return outBuf;
					}
				}
			}
		}
		
		// No function call had to be resolved.
		memcpy(outBuf.Begin(), disasm.CompleteInstr, strlen(disasm.CompleteInstr) + 1);
		
		// Clean up and return the instruction string.
		outBuf.Strlen();
		return outBuf;
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
	SIZE_T outputVal = 0;
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

		while (disasm.VirtualAddr < address)
		{
			const int len = CryDisasm(&disasm);
			if (len == UNKNOWN_OPCODE)
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
void RefreshExecutablePages(Vector<DisasmMemoryRegion>& pages)
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
		        DisasmMemoryRegion memReg;
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