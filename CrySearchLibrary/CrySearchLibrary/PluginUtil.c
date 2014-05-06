#include "../SDK/Plugin.h"

// Holds the friendly names for plugin types.
const char* PluginTypeLookupTable[] =
{
	"Unknown",
	"Dump Engine"
};

const char* GetPluginTypeFriendlyName(const DWORD Type)
{
	return PluginTypeLookupTable[Type];
}