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
#define CRYPLUGIN_UNKNOWN			0x0
#define CRYPLUGIN_DUMPER			0x1

// Plugin state definitions.
#define CRYPLUGIN_STATE_UNKNOWN		0
#define CRYPLUGIN_STATE_LOADED		1

// Flag definitions for plugins, sorted by plugin type.
// Plugin generic flags.
#define PLUGIN_WANTS_TAB_OUTPUT		0x1

// Dumper engine flags.
#define PLUGIN_CLASS_DEFAULT		0x80

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
	// Currently, this field is reserved and not used by CrySearch.
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

// Retrieves the information about the plugin author and possible credits.
// The string is user-defined and will be displayed in a message box inside CrySearch.
// Writing an about string for a plugin requires some attention. Use '&' for newlines instead of '\r\n' for example.
// For more information, and more detailed/better looking about messages, take a look at the QTF format on http://www.ultimatepp.org/
typedef void (__stdcall* CryGetPluginAboutProc)(char** const pOutputString);

// ------------------------------------------------------------------------------------------------------------------------------

// Dumper Engine function definitions.

// Creates a dump of a module inside a process.
// Returns TRUE if the dump succeeded and FALSE otherwise. Partial dump may or may not result in TRUE depending on the developers intentions.
typedef const BOOL (__stdcall* CreateModuleDumpProc32)(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName);
typedef const BOOL (__stdcall* CreateModuleDumpProc64)(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName);