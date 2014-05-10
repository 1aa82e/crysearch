#include "../../../CrySearchLibrary/SDK/Plugin.h"

CRYPLUGINHEADER SectionDumperPluginHeader;

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = (char*)dest;
	const char *s2 = (char*)src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}

const BOOL __stdcall CryGetPluginInformation(PCRYPLUGINHEADER* const pInfoBuffer)
{
	*pInfoBuffer = &SectionDumperPluginHeader;

	return TRUE;
}

const BOOL __stdcall CryInitializePlugin()
{
	SectionDumperPluginHeader.PluginType = CRYPLUGIN_DUMPER;
	SectionDumperPluginHeader.PluginName = "CrySearch IntelliDumper";
	SectionDumperPluginHeader.MajorVersion = 1;
	SectionDumperPluginHeader.MinorVersion = 0;
	SectionDumperPluginHeader.PluginState = CRYPLUGIN_STATE_LOADED;

	return TRUE;
}

const BOOL __stdcall CreateModuleDump32(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName)
{
	return TRUE;
}

#ifdef _WIN64
const BOOL __stdcall CreateModuleDump64(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName)
{
	return TRUE;
}
#endif

void __stdcall CryDestroyPlugin()
{

}