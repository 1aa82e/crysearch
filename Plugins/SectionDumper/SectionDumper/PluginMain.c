#include "../../../CrySearchLibrary/SDK/Plugin.h"

CRYPLUGINHEADER SectionDumperPluginHeader;

const BOOL __stdcall CryGetPluginInformation(PCRYPLUGINHEADER* const pInfoBuffer)
{
	*pInfoBuffer = &SectionDumperPluginHeader;

	return TRUE;
}

const BOOL __stdcall CryInitializePlugin()
{
	SectionDumperPluginHeader.PluginType = CRYPLUGIN_DUMPER;
	SectionDumperPluginHeader.PluginName = "CrySearch Section Dumper";
	SectionDumperPluginHeader.MajorVersion = 1;
	SectionDumperPluginHeader.MinorVersion = 0;
	SectionDumperPluginHeader.PluginState = CRYPLUGIN_STATE_LOADED;

	return TRUE;
}

void __stdcall CryDestroyPlugin()
{

}