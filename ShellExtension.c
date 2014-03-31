#include <Windows.h>

// Creates the registry key for extension association registration.
void CreatePathCommand(const char* const extension, const char* const action, char* const outString)
{
	const char* subStr = "\\Shell\\";
	const char* commandPart = "\\command\\";
	DWORD index = 0;
	int curStringLength = strlen(extension);
	
	// Set the file extension.
	memcpy(outString, extension, curStringLength);
	index += curStringLength;
	
	// Set the subkey.
	curStringLength = strlen(subStr);
	memcpy(outString + index, subStr, curStringLength);	
	index += curStringLength;
	
	// Set the action.
	curStringLength = strlen(action);
	memcpy(outString + index, action, curStringLength);
	index += curStringLength;
	
	// Set the command part.
	curStringLength = strlen(commandPart);
	memcpy(outString + index, commandPart, curStringLength);
	index += curStringLength;
}

// Registers the CrySearch Address Table file extension with the currently running CrySearch.
// Returns TRUE if the registration succeeded and FALSE otherwise.
const BOOL RegisterAddressTableExtension()
{
	HKEY key;
	const char* fileDesc = "CrySearch Address Table";
	const char* extension = ".csat";
	
	// Create a registry key for the address table file extension.
	if (RegCreateKeyEx(HKEY_CLASSES_ROOT, extension, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS)
	{
		// Create the command string for the second registry key action.
		char pathCommand[MAX_PATH];
		CreatePathCommand(extension, "Open with CrySearch", pathCommand);	
		
		RegSetValueEx(key, NULL, 0, REG_SZ, fileDesc, strlen(fileDesc));
		RegCloseKey(key);
		
		// Create a registry key to save the path to the executable that opens address tables.
		if (RegCreateKeyEx(HKEY_CLASSES_ROOT, pathCommand, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) != ERROR_SUCCESS)
		{
			return FALSE;
		}
		
		// Get the working directory of the application to set as command string.
		if (!GetModuleFileName(NULL, pathCommand, MAX_PATH))
		{
			RegCloseKey(key);
			return FALSE;
		}
		
		RegSetValueEx(key, NULL, 0, REG_SZ, pathCommand, strlen(pathCommand));
		RegCloseKey(key);
		
		return TRUE;
	}
	
	return FALSE;
}