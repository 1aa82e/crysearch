#include "../../../CrySearchLibrary/SDK/Plugin.h"

CRYPLUGINHEADER SectionDumperPluginHeader;
char creditArray[128]; //"CrySearch Alternate Core Function Plugin&&written by evolution536"

#define ALIGN_ADDR(addr, alignment) (addr % alignment) ? (addr + alignment - (addr % alignment)) : (addr)

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = (char*)dest;
	const char *s2 = (char*)src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}

const bool __stdcall CryGetPluginInformation(PCRYPLUGINHEADER* const pInfoBuffer)
{
	*pInfoBuffer = &SectionDumperPluginHeader;

	return TRUE;
}

void __stdcall CryGetPluginAbout(char** const pOutputString)
{
	*pOutputString = creditArray;
}

const bool __stdcall CryInitializePlugin()
{
	DWORD* iterator = (DWORD*)creditArray;

	// Initialize the plugin header with information.
	memset(&SectionDumperPluginHeader, 0, sizeof(CRYPLUGINHEADER));
	SectionDumperPluginHeader.PluginFeatures |= CRYPLUGIN_COREFUNC_OVERRIDE;
	SectionDumperPluginHeader.PluginName = "CryAlternateFunc";
	SectionDumperPluginHeader.MajorVersion = 1;
	SectionDumperPluginHeader.MinorVersion = 0;
	SectionDumperPluginHeader.Flags = (PLUGIN_CORE_OPEN_PROCESS | PLUGIN_CORE_PROTECT_PROCESS_MEMORY | PLUGIN_CORE_READ_PROCESS_MEMORY | PLUGIN_CORE_WRITE_PROCESS_MEMORY);
	SectionDumperPluginHeader.PluginState = CRYPLUGIN_STATE_LOADED;

	// Fill the credit obf string array with its values.
	*iterator++ = 0x53797243;
	*iterator++ = 0x63726165;
	*iterator++ = 0x6c412068;
	*iterator++ = 0x6e726574;
	*iterator++ = 0x20657461;
	*iterator++ = 0x65726f43;
	*iterator++ = 0x6e754620;
	*iterator++ = 0x6f697463;
	*iterator++ = 0x6c50206e;
	*iterator++ = 0x6e696775;
	*iterator++ = 0x72772626;
	*iterator++ = 0x65747469;
	*iterator++ = 0x7962206e;
	*iterator++ = 0x6f766520;
	*iterator++ = 0x6974756c;
	*iterator++ = 0x33356e6f;
	*iterator++ = 0x36;
	*iterator = 0x0;

	return TRUE;
}

HANDLE __stdcall CryOpenProcessRoutine(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

const bool __stdcall CryReadMemoryRoutine(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize)
{
	return !!ReadProcessMemory(handle, addr, buffer, size, outSize);
}

const bool __stdcall CryWriteMemoryRoutine(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize)
{
	return !!WriteProcessMemory(handle, addr, buffer, size, outSize);
}

const bool __stdcall CryProtectMemoryRoutine(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess)
{
	return !!VirtualProtectEx(handle, addr, size, newAccess, oldAccess);
}

void __stdcall CryProcessPluginEvent(CCryPluginEvent event, void* pParameter)
{
	switch (event)
	{
	case CRYPLUGINEVENT_PROCESS_OPENED:
		break;
	case CRYPLUGINEVENT_PROCESS_CLOSED:
		break;
	case CRYPLUGINEVENT_ERROR:
		break;
	}
}

void __stdcall CryDestroyPlugin()
{

}