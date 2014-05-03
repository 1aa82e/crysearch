#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#pragma warning(disable : 4996)

// Uses the cpuid instruction to retrieve information about the supported features by the processor.
// The supported values are displayed in the about dialog.
void GetProcessorSupportInformation(char pProcInformationString[128])
{
	BOOL sse;
	BOOL sse2;
	BOOL sse3;
	BOOL ssse3;
	BOOL sse41;
	BOOL sse42;
	BOOL avx;
	BOOL mmx;
	BOOL vtx;
	BOOL htt;
	BOOL pae;
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
	pae = CPUInfo[3] & (1 << 6);
	mmx = CPUInfo[3] & (1 << 23);
	sse = CPUInfo[3] & (1 << 25);
	sse2 = CPUInfo[3] & (1 << 26);
	htt = CPUInfo[3] & (1 << 28);
	
	// Create output string to display to the user.
	/*sprintf_s(pProcInformationString, 128, "\1[+70 Your processor supports: %s%s%s%s%s%s%s%s%s%s%s.]", sse ? "SSE, " : "", sse2 ? "SSE2, " : ""
		, sse3 ? "SSE3, " : "", ssse3 ? "SSSE3, " : "", sse41 ? "SSE4.1, " : "", sse42 ? "SSE4.2, " : "", mmx ? "MMX, " : ""
		, avx ? "AVX, " : "", vtx ? "VT, " : "", htt ? "HTT, " : "", pae ? "PAE, " : "");*/

	strcpy(pProcInformationString, prefixString);

	if (sse)
	{
		strcat(pProcInformationString, "SSE, ");
	}
	if (sse2)
	{
		strcat(pProcInformationString, "SSE2, ");
	}
	if (sse3)
	{
		strcat(pProcInformationString, "SSE3, ");
	}
	if (ssse3)
	{
		strcat(pProcInformationString, "SSSE3, ");
	}
	if (sse41)
	{
		strcat(pProcInformationString, "SSE4.1, ");
	}
	if (sse42)
	{
		strcat(pProcInformationString, "SSE4.2, ");
	}
	if (mmx)
	{
		strcat(pProcInformationString, "MMX, ");
	}
	if (avx)
	{
		strcat(pProcInformationString, "AVX, ");
	}
	if (vtx)
	{
		strcat(pProcInformationString, "VT, ");
	}
	if (htt)
	{
		strcat(pProcInformationString, "HTT, ");
	}
	if (pae)
	{
		strcat(pProcInformationString, "PAE, ");
	}

	strcat(pProcInformationString, ".]");
	
	// If the last character of the string is a comma, truncate it.
	lastChar = strlen(pProcInformationString) - 4;
	if (pProcInformationString[lastChar] == ',')
	{
		pProcInformationString[lastChar] = '.';
		pProcInformationString[lastChar + 1] = ']';
		pProcInformationString[lastChar + 2] = 0;
	}
}