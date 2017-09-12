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

// Refreshes the pages that may contain code to be disassembled.
void RefreshExecutablePages(Vector<MemoryRegion>& pages);

// Retrieves an instruction that precedes that one at the specified address.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob);

// Retrieves an instruction at the specified address.
String DisasmGetLine(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob);

// Retrieves only the instruction bytes at the specified address.
void DisasmForBytes(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob, Vector<char>* const optOutMasking);

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, const cs_mode architecture, ArrayOfBytes* const outAob);

#endif