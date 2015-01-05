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
 *		and operate plugins. Always try to use the latest SDK version as it may change through versions.
 */

#include <Windows.h>

// Plugin feature definitions. For different features/actions CrySearch looks for plugins that implement a feature.
// A featureless plugin should have CRYPLUGIN_UNKNOWN defined. For example, to dump a module, CrySearch will
// look for plugins that have CRYPLUGIN_DUMPER defined. A plugin may have multiple types defined (Bitwise OR).
// Adding your own feature flags is possible by defining a new bitflag above the highest Crysearch-defined flag.
// Note that CrySearch may add feature flags in future versions, overwriting custom defined ones. The maximum 
// amount of available feature flags is 32 as the flags are stored in a DWORD field.
#define CRYPLUGIN_UNKNOWN			0x0
#define CRYPLUGIN_DUMPER			0x1

// Plugin state definitions. CrySearch uses state values to indicate whether the plugin is in a specific state.
// CRYPLUGIN_STATE_LOADED indicates that the plugin has finished its initialization routine(s), is fully loaded into
// CrySearch address space and ready to use. Note that your plugin is required to take this into account. Not takng
// this into account may result in unexpected behavior. Undefined plugin state means that CrySearch cannot keep track of it.
#define CRYPLUGIN_STATE_UNKNOWN		0
#define CRYPLUGIN_STATE_LOADED		1

// Flag definitions for plugins, sorted by plugin type. Plugin flags may or may not be used by CrySearch. It is allowed
// to define custom flags for your own plugin. Below are the plugin definitions, sorted by plugin type.

// The following flags are generic plugin flags. PLUGIN_WANTS_TAB_OUTPUT indicates that the plugin would like CrySearch
// to provide the plugin an output window in the bottom pane of CrySearch. The plugin may write data to it.
#define PLUGIN_WANTS_TAB_OUTPUT		0x1

// The following flags are specific to dumper plugins. PLUGIN_CLASS_DEFAULT indicates that a dumper plugin is offering
// to be the default dumper. When dumping all modules in a process, CrySearch will look for the first plugin that offers
// itself as default dumper. If no plugins do so, it will take the first available dumper.
#define PLUGIN_CLASS_DEFAULT		0x80

// Contains vital information about the plugin. This information should be used to idenfity loaded plugins.
// Every plugin should have exactly one instance of this structure defined. It is required to have lifetime availability
// and may not be moved to another place in memory. Not complying to these requirements may result in undefined behavior.
typedef struct tagCRYPLUGINHEADER
{
	// Represents the features a plugin implements. This is defined by a set of flags that are defined as plugin feature flags.
	DWORD PluginFeatures;

	// Represents the human-readable name of the plugin. This should be a null-terminated ANSI string that requires lifetime
	// availability. The string may not be moved in memory once it has been made available.
	LPSTR PluginName;

	// Two double byte version numbers that indicate the version of the plugin. The version numbers are not used by CrySearch
	// to control the program flow. The version number is displayed by CrySearch and can be used to indicate the version to the user.
	WORD MajorVersion;
	WORD MinorVersion;

	// Represents the state of the plugin. This field may be used by a plugin but it is not required. This field is currently
	// reserved and not used by CrySearch. Therefore it may be freely used by a plugin to store data.
	DWORD PluginState;

	// Contains flags that are associated with the plugin. This field may be used by a plugin but it is not required. Possible
	// flags are defined by the plugin flag definitions. They can be appended using bitwise operations.
	DWORD Flags;

	// Reserved field that is not used by CrySearch. May be freely used by a plugin to store data or a pointer to data.
	// This implies ofcourse that any memory management must be handled by the plugin itself.
	LPVOID Reserved;
} CRYPLUGINHEADER, *PCRYPLUGINHEADER;

// Defines the plugin event type identifier. When CrySearch needs a plugin to process an event, this type is passed
// into the CryProcessPluginEvent function to identify the type of event. The event cannot be combined with other events.
typedef DWORD CCryPluginEvent;

// CrySearch builtin plugin event type definitions. Only one event can be specified at a time. You can define your own event
// type with a value higher than CRYPLUGINEVENT_USER.
#define CRYPLUGINEVENT_PROCESS_OPENED		0x1
#define CRYPLUGINEVENT_PROCESS_CLOSED		0x2
#define CRYPLUGINEVENT_ERROR				0x3
#define CRYPLUGINEVENT_DEBUGGER_ATTACHED	0x4
#define CRYPLUGINEVENT_DEBUGGER_DETACHED	0x5
#define CRYPLUGINEVENT_USER					0x100

// Retrieves a pointer to the plugin header struct of the loaded plugin. This pointer can be retrieved because the plugin should 
// be loaded at time of calling, hence the structure should be in available memory. The pointer returned by this may not be freed
// by the caller until the plugin is unloaded. A function called 'CryGetPluginInformation' with the following function prototype
// must be exported by a plugin, should it be loaded succesfully.
typedef const BOOL (__stdcall* CryGetPluginInformationProc)(PCRYPLUGINHEADER* const pInfoBuffer);

// Initializes the plugin. Implement this function in a new plugin to do any initialization work. Return TRUE if the initialization
// succeeded and FALSE otherwise. A function called 'CryInitializePlugin' with the following function prototype must be exported by
// a plugin, should it be loaded succesfully.
typedef const BOOL (__stdcall* CryInitializePluginProc)();

// Executes any cleanup operations before a plugin is unloaded. A function called 'CryDestroyPlugin' with the following function
// prototype must be exported by a plugin, should it be loaded succesfully.
typedef void (__stdcall* CryDestroyPluginProc)();

// Retrieves information about the plugin author and possible credits. The string is user-defined. CrySearch uses this string when
// the user requests the about box in the plugins window. Writing an about string for a plugin requires some attention. Use '&' for
// newlines instead of '\r\n'. The string must have lifetime availability and must not be moved after the plugin is loaded. For more
// information and more details about writing an about message, take a look at the QTF format on http://www.ultimatepp.org/. A function
// called 'CryGetPluginAbout' with the following function prototype must be exported by a plugin, should it be loaded succesfully.
typedef void (__stdcall* CryGetPluginAboutProc)(char** const pOutputString);

// Processes events from CrySearch. This function is called when CrySearch fires plugin events. A parameter may be supplied but may also
// be NULL. This function, called 'CryProcessPluginEvent' and with the following prototype, must be exported by a plugin for it to be able
// to receive events from CrySearch. It must be implemented in a thread-safe way, Meaning that it may be called by CrySearch multiple times
// to dispatch different events at the same time. If this function is not implemented, the plugin will not receive any events. The
// 'pParameter' parameter will have the following value(s) when called by CrySearch with 'event' parameter:
// 'event' ------------------------- | 'pParameter'
// CRYPLUGINEVENT_PROCESS_OPENED     | The process ID of the process that was opened: (void*)pid;
// CRYPLUGINEVENT_PROCESS_CLOSED     | NULL;
// CRYPLUGINEVENT_DEBUGGER_ATTACHED  | NULL;
// CRYPLUGINEVENT_DEBUGGER_DETACHED  | NULL;
typedef void (__stdcall* CryProcessPluginEventProc)(CCryPluginEvent event, void* pParameter);

// ------------------------------------------------------------------------------------------------------------------------------

// The following functions, definitions and structures apply to specific types or implementations of plugins. Each plugin-specific
// section is seperated by a line of dashes like the one above.

// The following functions create a dump of a x86, Wow64 or x64 module inside a process. If a module in a x86 or Wow64 process needs to be
// dumped, use the 32-bit function. Otherwise, use the 64-bit function. A custom dumper plugin should implement and export both functions.
// It takes the following parameters:
// hProcess     | A valid handle to the process that contains the module to dump. The handle must have PROCESS_VM_READ access rights;
// moduleBase   | The base address of the module. If this address is not the actual module base address, the dump will fail;
// moduleSize   | The module size. This is the size that the dumper will read from the memory and written to the output file;
// fileName     | The path to the output file. If the file already exists it will be overwritten.
// Returns TRUE if the dump succeeded and FALSE otherwise. Partial dump may or may not result in TRUE depending on the developers intentions.
typedef const BOOL (__stdcall* CreateModuleDumpProc32)(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName);
typedef const BOOL (__stdcall* CreateModuleDumpProc64)(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName);