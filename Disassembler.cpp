#include "Disassembler.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"

// ---------------------------------------------------------------------------------------------

// Retrieves the line of disassembly at the specified address. The return value is the string
// representation of the disassembled line. A pointer to receive the bytes can be specified.
String DisasmGetLine(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob)
{
	// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
	csh handle;
	if (cs_open(CS_ARCH_X86, architecture, &handle) != CS_ERR_OK)
	{
		return "";
	}
	
	// Read the actual memory buffer from the specified address.
	const DWORD bufferLength = architecture == CS_MODE_64 ? 20 : 16;
    Byte buffer[20];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
	
	// Disassemble the instruction at the specified address.
	cs_insn* insn;
	const size_t count = cs_disasm(handle, buffer, bufferLength, address, 1, &insn);
	
	// Was the disassembly succesful?
	if (count > 0)
	{
		// Place the disassembled byte sequence in the output parameter if it was specified.
		if (outAob)
		{
			outAob->Allocate(insn->size);
			memcpy(outAob->Data, insn->bytes, insn->size);
		}
		
		// Free the memory buffer Capstone allocated.
		cs_free(insn, count);
		
		// Construct the complete instruction string and return it.
		return Format("%s %s", insn->mnemonic, insn->op_str);
	}
	
	// Close the Capstone handle.
	cs_close(&handle);

	return "";
}

// Retrieves only the instruction bytes at the specified address. It's wise to input an array of 8 in size for the 'optOutMasking' parameter.
void DisasmForBytes(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob, Vector<char>* const optOutMasking)
{
	// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
	csh handle;
	cs_open(CS_ARCH_X86, architecture, &handle);

	// Turn on the detailed output option.
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	
	// Read the actual memory buffer from the specified address.
	const DWORD bufferLength = architecture == CS_MODE_64 ? 20 : 16;
    Byte buffer[20];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
	
	// Disassemble the instruction at the specified address.
	cs_insn* insn;
	const size_t count = cs_disasm(handle, buffer, bufferLength, address, 1, &insn);
	
	// Was the disassembly succesful?
	if (count > 0)
	{
		// Place the disassembled byte sequence in the output parameter if it was specified.
		if (outAob)
		{
			outAob->Allocate(insn->size);
			memcpy(outAob->Data, insn->bytes, insn->size);
		}
		
		// If the caller requested masking information, let's output it.
		if (optOutMasking)
		{
			// First fill the output with x's. Further on, some may be replaced by ?'s.
			optOutMasking->Set(0, 'x', insn->size);
			
			// Check whether this instruction has IMM operands.
			cs_detail* detail = insn->detail;
			if (cs_op_count(handle, insn, X86_OP_IMM) > 0)
			{
				// Get IMM operand index.
				const int immIndex = cs_op_index(handle, insn, X86_OP_IMM, 1);
				if (immIndex != -1)
				{
					// If we have a relative CALL (0xE8) or JMP (0xE9) instruction, the last bytes are the immediate.
					if (insn->bytes[0] == 0xE8 || insn->bytes[0] == 0xE9)
					{
						// Mask out all bytes except the first.
						optOutMasking->Set(1, '?', insn->size - 1);
					}
					// Look for the index of the immediate value.
					else if (detail->x86.operands[immIndex].size == sizeof(__int64))
					{
						// We want to look for a 64-bit immediate value.
						for (unsigned int c = 0; c < insn->size; ++c)
						{
							if (*((__int64*)&buffer[c]) == detail->x86.operands[immIndex].imm)
							{
								// Mask the immediate value out.
								optOutMasking->Set(c, '?', sizeof(__int64));
								break;
							}
						}
					}
					else
					{
						// We want to look for a 32-bit immediate value.
						for (unsigned int c = 0; c < insn->size; ++c)
						{
							if (*((DWORD*)&buffer[c]) == (DWORD)detail->x86.operands[immIndex].imm)
							{
								// Mask the immediate value out.
								optOutMasking->Set(c, '?', sizeof(DWORD));
								break;
							}
						}
					}
				}
			}
		}
	}
	else
	{
		// The instruction could not be disassembled. Just place the input byte in the output.
		if (outAob)
		{
			outAob->Allocate(sizeof(Byte));
			outAob->Data[0] = *buffer;
		}
	}

	// Free the memory buffer Capstone allocated.
	cs_free(insn, count);
	
	// Reset default option state.
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

	// Close the Capstone handle.
	cs_close(&handle);
}

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, const cs_mode architecture)
{
	// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
	csh handle;
	if (cs_open(CS_ARCH_X86, architecture, &handle) != CS_ERR_OK)
	{
		return "";
	}
	
	// Turn on the detailed output option.
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	
	// Read the actual memory buffer from the specified address.
	const DWORD bufferLength = architecture == CS_MODE_64 ? 20 : 16;
    Byte buffer[20];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, bufferLength, NULL);
	
	// Disassemble the instruction at the specified address.
	cs_insn* insn;
	const size_t count = cs_disasm(handle, buffer, bufferLength, address, 1, &insn);
	
	// Was the disassembly succesful?
	String completeStr;
	if (count > 0)
	{
		completeStr.Reserve(MAX_PATH);

		// Construct the complete instruction string.
		bool matchedToFunction = false;
		completeStr = insn->mnemonic;
		completeStr += " ";
		
		// If the address value of this instruction contains something, it may refer to a function in the import address table.
		cs_detail* detail = insn->detail;
		if (cs_insn_group(handle, insn, X86_GRP_CALL))
		{
			// Should we try to resolve a function call?
			if (SettingsFile::GetInstance()->GetResolveDisasmImportedFunctions())
			{
				__int64 disp_imm_value = 0;
	
				// Find a MEM operand and takes its value.
				if (cs_op_count(handle, insn, X86_OP_MEM) > 0)
				{
					// Get MEM operand index.
					const int memIndex = cs_op_index(handle, insn, X86_OP_MEM, 1);
					if (memIndex != -1)
					{
						disp_imm_value = detail->x86.operands[memIndex].mem.disp;
					}
				}
				// Find an IMM operand and take its value.
				else if (cs_op_count(handle, insn, X86_OP_IMM) > 0)
				{
					// Get IMM operand index.
					const int immIndex = cs_op_index(handle, insn, X86_OP_IMM, 1);
					if (immIndex != -1)
					{
						disp_imm_value = detail->x86.operands[immIndex].reg;
					}
				}
	
				// Does the displacement value of the call argument refer to a thunk?
				if (disp_imm_value)
				{
					String functionName;
					if (LoadedProcessPEInformation.FindImportedFunctionAddress((SIZE_T)disp_imm_value, functionName))
					{
						// The instruction refers to an imported function.
						completeStr += functionName;
						matchedToFunction = true;
					}
					else
					{
						// Disassemble the instruction at the argument address to find out whether it actually is a thunk.
						if (CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)disp_imm_value, buffer, bufferLength, NULL))
						{
							cs_insn* thunkInsn;
							const size_t thunkCount = cs_disasm(handle, buffer, bufferLength, disp_imm_value, 1, &thunkInsn);
							if (thunkCount > 0)
							{
								// Is the instruction actually an unconditional jump? If so, match the address to thunk addresses in the import table.
								if (cs_insn_group(handle, thunkInsn, X86_GRP_JUMP))
								{
									// Try to resolve the function address to an imported function name.
									if (LoadedProcessPEInformation.FindImportedFunctionAddress((SIZE_T)thunkInsn->detail->x86.disp, functionName))
									{
										// The instruction refers to an imported function.
										completeStr += functionName;
										matchedToFunction = true;
									}
								}
							}
	
							// Free the thunk memory buffer.
							cs_free(thunkInsn, thunkCount);
						}
					}
				}
			}
		}

		// The instruction does not refer to an imported function, complete the instruction string regularly.
		if (!matchedToFunction)
		{
			completeStr += insn->op_str;
		}
	}
	else
	{
		// Capstone could not disassemble this instruction. We make some textual representation for this unknown byte.
		completeStr = "db 0x" + BytesToString(buffer, 1);
	}

	// Free the memory buffer Capstone allocated.
	cs_free(insn, count);
	
	// Reset default option state.
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

	// Close the Capstone handle.
	cs_close(&handle);
	
	return completeStr;
}

// Retrieves the previous line of disassembly reflected against the specified address. The address inputted must
// be the address of a valid instruction line. The instruction size parameter specifies how big the desired
// instruction must be to have a match. This greatly decreases the chance of a mismatch.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob)
{
	MEMORY_BASIC_INFORMATION block;
	SIZE_T outputVal = 0;

	// Query the memory page this breakpoint occured in, so we can guarantee accurate instruction parsing.
	if (VirtualQueryEx(mMemoryScanner->GetHandle(), (void*)address, &block, sizeof(block)))
	{
		Byte* buffer = new Byte[block.RegionSize];
		CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)block.BaseAddress, buffer, block.RegionSize, NULL);

		// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
		csh handle;
		cs_open(CS_ARCH_X86, architecture, &handle);

		// Allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
		cs_insn* insn = cs_malloc(handle);
		const Byte* bufIteratorPtr = buffer;
		size_t code_size = block.RegionSize;
		uint64 iterAddress = (uint64)block.BaseAddress;
		uint64 prevAddress = iterAddress;

		// Disassemble one instruction a time & store the result into @insn variable.
		while (cs_disasm_iter(handle, &bufIteratorPtr, &code_size, &iterAddress, insn))
		{
			// Succesfully disassembled, check if this is the previous instruction.
			if (insn->address + insn->size == address)
			{
				// We found the address of the previous instruction.
				outputVal = (SIZE_T)insn->address;

				// If the caller wants bytes output, prepare it.
				if (outAob)
				{
					outAob->Allocate(insn->size);
					memcpy(outAob->Data, insn->bytes, insn->size);
				}

				break;
			}
		}

		delete[] buffer;

		// Free the memory buffer Capstone allocated.
		cs_free(insn, 1);

		// Close the Capstone handle.
		cs_close(&handle);
	}

	return outputVal;
}

// Retrieves a list of executable memory pages.
void GetExecutableMemoryPagesList(Vector<MemoryRegion>& outList)
{
	SIZE_T incAddress = 0;
	MEMORY_BASIC_INFORMATION block;
	
	while (VirtualQueryEx(mMemoryScanner->GetHandle(), (void*)incAddress, &block, sizeof(block)))
	{
		// We need a readable page, and one that doesn't trigger an exception in the target process.
		if ((block.State == MEM_COMMIT) && (!(block.Protect & PAGE_GUARD)) && (!(block.Protect & PAGE_NOACCESS)))
		{
			// Is it an executable memory page?
			if ((block.Protect & MEM_EXECUTABLE) != 0)
			{
				// Memory region is valid for scanning, add it to the region list.
				MemoryRegion memRegion;
				memRegion.BaseAddress = (SIZE_T)block.BaseAddress;
			    memRegion.MemorySize = block.RegionSize;
			    outList << memRegion;
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

// Retrieves the memory page that contains the specified address. If no address is specified,
// it will return the first executable page.
const bool GetMemoryPageByAddress(const SIZE_T address, MemoryRegion& memReg, AuxMemRegStruct* const outAuxMemRegs)
{
	int foundIndex = -1;
	
	// Retrieve a list of executable memory pages.
	Vector<MemoryRegion> memVec;
	memVec.Reserve(128);
	GetExecutableMemoryPagesList(memVec);
	
	// Loop through the pages to find several important ones.
	const int memCount = memVec.GetCount();
	for (int i = 0; i < memCount; ++i)
	{
	    // Check whether the current page contains the specified address.
	    if (address >= memVec[i].BaseAddress && address <= memVec[i].BaseAddress + memVec[i].MemorySize)
	    {
			// Save the index of the found page for later.
			foundIndex = i;
	    }
	}

	// Did the caller ask for the previous and next pages?
	if (outAuxMemRegs)
	{
		// If we don't want to look for address containment (address = 0), just return
		// the first page we found.
		if (!address)
		{
			// If the page containing the specified address was not found, return the first.
			foundIndex = 0;
			memReg = memVec[foundIndex];
		}
		
		// Is there a preceding page?
		if (foundIndex > 0)
		{
			memReg = memVec[foundIndex];
			outAuxMemRegs->Previous = memVec[foundIndex - 1];
		}
		else
		{
			outAuxMemRegs->Previous.BaseAddress = 0;
			outAuxMemRegs->Previous.MemorySize = 0;
		}
		
		// Is the a successing page?
		if (foundIndex < memVec.GetCount() - 1)
		{
			memReg = memVec[foundIndex];
			outAuxMemRegs->Next = memVec[foundIndex + 1];
		}
		else
		{
			outAuxMemRegs->Next.BaseAddress = 0;
			outAuxMemRegs->Next.MemorySize = 0;
		}
	}
	
	return (foundIndex != -1);
}

// Disassembles a region of memory from some starting address to some ending address.
// Once the killSwitch becomes false, the disassembling stops.
void DisassembleRegion(const SIZE_T address, const SIZE_T size, const cs_mode architecture, Vector<LONG_PTR>& outInsts, volatile bool& killSwitch)
{
	// Query virtual pages inside target process.
    Byte* const buffer = new Byte[size];
    CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, buffer, size, NULL);
    
    // Reserve an approximated buffer for instruction lines.
    outInsts.Reserve((int)size / 4);
	
	// Open Capstone disassembler in x86 mode, for either x86_32 or x86_64.
	csh handle;
	cs_open(CS_ARCH_X86, architecture, &handle);
    
    // Allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
	cs_insn* insn = cs_malloc(handle);
	const Byte* bufIteratorPtr = buffer;
	size_t code_size = size;
	uint64 iterAddress = address;
	uint64 prevAddress = iterAddress;
	
	// Keep disassembling until we reach the end of the specified input memory block.
	do
	{
		// Disassemble one instruction a time & store the result into @insn variable.
		while (cs_disasm_iter(handle, &bufIteratorPtr, &code_size, &iterAddress, insn))
		{
			// Disassembled succesfully, add a new line.
			outInsts.Add((SIZE_T)prevAddress);
			prevAddress = iterAddress;
		}

		// Check if we encountered an address that Capstone could not disassemble.
		if (cs_errno(handle) == CS_ERR_OK && iterAddress < address + size)
		{
			outInsts.Add((SIZE_T)iterAddress++);
			prevAddress = iterAddress;
		}
	}
	while (prevAddress < address + size && killSwitch);
	
	// Release the cache memory when done.
	cs_free(insn, 1);

	// Close the Capstone handle.
	cs_close(&handle);
		
	// Clean up used buffers and shrink instruction line buffer.
	outInsts.Shrink();
	delete[] buffer;
}