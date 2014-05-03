#pragma once

/*
 *		CrySearch.h - evolution536
 *
 *		CrySearch plugin SDK header. Contains functions and definitions including documentation about 
 *		how to develop plugins for CrySearch. Please include CrySearch.h in a new plugin to gain
 *		access to CrySearch library functions. Include this header to only gain access to plugin
 *		requirements.
 *
 *		When writing a new plugin, the functions below must be implemented, as well as an instance of
 *		the header structure. The structure must contain information that CrySearch can use to idenfity
 *		and operate plugins.
 */

#include <Windows.h>

// Plugin type definitions.
#define CRYPLUGIN_DUMPER			0x1

// Plugin state definitions.
#define CRYPLUGIN_STATE_LOADED		0x1

// Contains information about the type of plugin. This information should be used to idenfity loaded plugins.
// Every plugin should have exactly one piece of this structure in its global memory.
typedef struct tagCRYPLUGINHEADER
{
	// Represents the type of plugin. This is defined by a set of numbers.
	DWORD PluginType;

	// Represents the human-readable name of the plugin. This should be a statically allocated null-terminated
	// string that has application lifetime.
	LPSTR PluginName;

	// Two double byte version numbers that indicate the version of the plugin.
	WORD MajorVersion;
	WORD MinorVersion;

	// Represents the state of the plugin. May or may not be utilized by a plugin.
	DWORD PluginState;

	// Contains flags that are associated with the plugin. May or may not be utilized by a plugin.
	DWORD Flags;
} CRYPLUGINHEADER, *PCRYPLUGINHEADER;

// Retrieves a pointer to the plugin header struct of the loaded plugin.
// This pointer should be retrieved easily since the DLL is loaded and the structure should be in global memory.
// Therefore the pointer returned should not be deleted.
typedef const BOOL (__stdcall* CryGetPluginInformationProc)(PCRYPLUGINHEADER* const pInfoBuffer);

// Initializes the plugin. Implement this function in a new plugin to do any initialization work.
// Return TRUE if the initialization succeeded and FALSE otherwise.
typedef const BOOL (__stdcall* CryInitializePluginProc)();

// Destroys the plugin. Implement this function in a new plugin to do any destruction.
// This function is called before the plugin is unloaded.
typedef void (__stdcall* CryDestroyPluginProc)();