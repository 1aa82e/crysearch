#ifndef _CrySearch_Disassembler_h_
#define _CrySearch_Disassembler_h_

#include <Core/Core.h>

using namespace Upp;

// Set BeaEngine to use __stdcall as default calling convention.
#define BEA_USE_STDCALL

#include "MemoryScanner.h"

// Include Capstone library headers.
#include "Capstone/include/capstone.h"

// Dynamically link to disassembler library.
#ifdef _WIN64
	#pragma comment(lib, "Capstone/lib/x64/capstone.lib")
#else
	#pragma comment(lib, "Capstone/lib/x86/capstone.lib")
#endif

// Auxiliary struct that gives the previous and next memory page for a given page.
struct AuxMemRegStruct
{
	MemoryRegion Previous;
	MemoryRegion Next;
};

// Retrieves the memory page that contains the specified address. If no address is specified,
// it will return the first executable page.
const bool GetMemoryPageByAddress(const SIZE_T address, MemoryRegion& memReg, AuxMemRegStruct* const outAuxMemRegs);

// Retrieves an instruction that precedes that one at the specified address.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob);

// Retrieves an instruction at the specified address.
String DisasmGetLine(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob);

// Retrieves only the instruction bytes at the specified address.
void DisasmForBytes(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob, Vector<char>* const optOutMasking);

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, const cs_mode architecture);

#endif