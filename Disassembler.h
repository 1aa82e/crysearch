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

int __stdcall CryDisasm(LPDISASM lpDisasm);

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

void RefreshExecutablePages(Vector<MemoryRegion>& pages);
String DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

#endif