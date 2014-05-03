#include <Windows.h>

// Plugin type definitions.
#define CRYPLUGIN_DUMPER	0x1

// Contains information about the type of plugin. This information should be used to idenfity loaded plugins.
// Make sure the structure members do not need to be destroyed, or destroy them yourself. CrySearch does not destroy them!
typedef struct tagCRYPLUGINHEADER
{
	DWORD PluginType;
	LPSTR PluginName;
} CRYPLUGINHEADER, *PCRYPLUGINHEADER;

// Retrieves information about a plugin.
#ifdef __cplusplus
extern "C"
{
#endif

const BOOL __stdcall CryGetPluginInformation(PCRYPLUGINHEADER const pInfoBuffer);
const BOOL __stdcall CryInitializePlugin();
void __stdcall CryDestroyPlugin();

#ifdef __cplusplus
}
#endif