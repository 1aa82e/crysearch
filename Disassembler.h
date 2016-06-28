#ifndef _CrySearch_Disassembler_h_
#define _CrySearch_Disassembler_h_

#include <Core/Core.h>

using namespace Upp;

// Set BeaEngine to use __stdcall as default calling convention.
#define BEA_USE_STDCALL

#include "MemoryScanner.h"
#include "BeaEngine/include/BeaEngine.h"

// Dynamically link to disassembler library.
#ifdef _WIN64
	#pragma comment(lib, "BeaEngine/lib/BeaEngine64.lib")
#else
	#pragma comment(lib, "BeaEngine/lib/BeaEngine.lib")
#endif

#ifdef _cplusplus
extern "C"
{
#endif

const int __stdcall CryDisasm(LPDISASM lpDisasm);

#ifdef _cplusplus
}
#endif

#ifdef _WIN64
	#define ASM_LINE_MAX_BYTES 19
#else
	#define ASM_LINE_MAX_BYTES 15
#endif

// Architecture definitions
enum ArchitectureDefinitions
{
	ARCH_X86 = 0,
	ARCH_X64 = 64
};

// Represents a memory region solely for disassembler use.
struct DisasmMemoryRegion : Moveable<DisasmMemoryRegion>
{
	SIZE_T BaseAddress;
	SIZE_T MemorySize;
};

// Refreshes the pages that may contain code to be disassembled.
void RefreshExecutablePages(Vector<DisasmMemoryRegion>& pages);

// Retrieves an instruction that precedes that one at the specified address.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves an instruction at the specified address.
String DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves only the instruction bytes at the specified address.
void DisasmForBytes(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

#endif