#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

// Uses the cpuid instruction to retrieve information about the supported features by the processor.
// The supported values are displayed in the about dialog.
void __stdcall GetProcessorSupportInformation(char pProcInformationString[128])
{
	BOOL sse;
	BOOL sse2;
	BOOL sse3;
	BOOL ssse3;
	BOOL sse41;
	BOOL sse42;
	BOOL mmx;
	BOOL vtx;
	BOOL fma;
	BOOL avx;
	BOOL avx2;
	BOOL tsx;
	int CPUInfo[4] = {-1};
	size_t lastChar = 0;
	char* prefixString = "\1[+70 Your processor supports: ";

	// Get basic CPU information and dissect this information into seperate variables.
	__cpuid(CPUInfo, 1);

	sse3 = CPUInfo[2] & (1 << 0);
	vtx = CPUInfo[2] & (1 << 5);
	ssse3 = CPUInfo[2] & (1 << 9);
	sse41 = CPUInfo[2] & (1 << 19);
	sse42 = CPUInfo[2] & (1 << 20);
	avx = CPUInfo[2] & (1 << 28);
	fma = CPUInfo[2] & (1 << 12);
	mmx = CPUInfo[3] & (1 << 23);
	sse = CPUInfo[3] & (1 << 25);
	sse2 = CPUInfo[3] & (1 << 26);
	
	// Get extended CPU information and dissect this information into seperate variables.
	__cpuid(CPUInfo, 7);

	avx2 = CPUInfo[1] & (1 << 5);
	tsx = CPUInfo[1] & (1 << 11);

	// Create output string to display to the user.
	strcpy_s(pProcInformationString, 128, prefixString);

	if (sse)
	{
		strcat_s(pProcInformationString, 128, "SSE, ");
	}
	if (sse2)
	{
		strcat_s(pProcInformationString, 128, "SSE2, ");
	}
	if (sse3)
	{
		strcat_s(pProcInformationString, 128, "SSE3, ");
	}
	if (ssse3)
	{
		strcat_s(pProcInformationString, 128, "SSSE3, ");
	}
	if (sse41)
	{
		strcat_s(pProcInformationString, 128, "SSE4.1, ");
	}
	if (sse42)
	{
		strcat_s(pProcInformationString, 128, "SSE4.2, ");
	}
	if (mmx)
	{
		strcat_s(pProcInformationString, 128, "MMX, ");
	}
	if (vtx)
	{
		strcat_s(pProcInformationString, 128, "VMX, ");
	}
	if (fma)
	{
		strcat_s(pProcInformationString, 128, "FMA3, ");
	}
	if (avx)
	{
		strcat_s(pProcInformationString, 128, "AVX, ");
	}
	if (avx2)
	{
		strcat_s(pProcInformationString, 128, "AVX2, ");
	}
	if (tsx)
	{
		strcat_s(pProcInformationString, 128, "TSX, ");
	}

	strcat_s(pProcInformationString, 128, ".]");
	
	// If the last character of the string is a comma, truncate it.
	lastChar = strlen(pProcInformationString) - 4;
	if (pProcInformationString[lastChar] == ',')
	{
		pProcInformationString[lastChar] = '.';
		pProcInformationString[lastChar + 1] = ']';
		pProcInformationString[lastChar + 2] = 0;
	}
}