#include <Windows.h>
#include <Shlwapi.h>

const char* fileDesc = "CrySearch Address Table";
const char* extension = ".csat";
const char* action = "Open with CrySearch";

// Creates the registry key for extension association registration.
void CreatePathCommand(const char* const extension, const char* const action, char* outString)
{
	const char* subStr = "\\Shell\\";
	const char* commandPart = "\\command\\";
	SIZE_T index = 0;
	SIZE_T curStringLength = strlen(extension);
	
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
	
	// Set a null terminator at the end of the string.
	*(outString + index) = 0;
}

// Registers the CrySearch Address Table file extension with the currently running CrySearch.
// Returns TRUE if the registration succeeded and FALSE otherwise.
const BOOL RegisterAddressTableExtension()
{
	HKEY key;

	// Create a registry key for the address table file extension.
	if (RegCreateKeyEx(HKEY_CLASSES_ROOT, extension, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS)
	{
		// Create the command string for the second registry key action.
		char pathCommand[MAX_PATH];
		CreatePathCommand(extension, action, pathCommand);	
		
		RegSetValueEx(key, NULL, 0, REG_SZ, fileDesc, (DWORD)strlen(fileDesc));
		RegCloseKey(key);
		
		// Create a registry key to save the path to the executable that opens address tables.
		if (RegCreateKeyEx(HKEY_CLASSES_ROOT, pathCommand, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) != ERROR_SUCCESS)
		{
			return FALSE;
		}
		
		pathCommand[0] = '"';
		// Get the working directory of the application to set as command string.
		if (!GetModuleFileName(NULL, pathCommand + 1, MAX_PATH))
		{
			RegCloseKey(key);
			return FALSE;
		}
		
		// Append an identifier for the first parameter to the command string.
		strcat_s(pathCommand, MAX_PATH, "\" \"%1\"");
		
		// Set the value inside the registry key.
		RegSetValueEx(key, NULL, 0, REG_SZ, pathCommand, (DWORD)strlen(pathCommand));
		RegCloseKey(key);
		
		return TRUE;
	}
	
	return FALSE;
}

// Deletes the file extension registration from the registry.
// Returns TRUE if the file extension was deleted succesfully or FALSE otherwise.
const BOOL DeleteAddressTableRegistration()
{
	char regKey[MAX_PATH];
	
	// Create the same path as during the registration function.
	CreatePathCommand(extension, action, regKey);
	
	// Delete the key.
	return SHDeleteKey(HKEY_CLASSES_ROOT, extension) == ERROR_SUCCESS ? TRUE : FALSE;
}

// Gets whether the CrySearch Address Table file extension is currently registered.
// Returns TRUE if the file extension is registered and FALSE otherwise.
// Beware that this function only returns TRUE if the registered path is exactly the same as the working directory of the current instance.
const BOOL GetIsAddressTableExtensionRegistered()
{
	HKEY key;
	char regKey[MAX_PATH];
	DWORD regLength = MAX_PATH;
	char exePath[MAX_PATH];
	
	// Create the same path as during the registration function.
	CreatePathCommand(extension, action, regKey);
	
	// Try to open the key. If it fails here the key probably doesn't even exist so no need to move on.
	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, regKey, 0, KEY_READ, &key) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	
	// The key exists. Now check if it exists on the correct architecture.
	RegQueryValueEx(key, NULL, NULL, NULL, regKey, &regLength);
	
	// Get the working directory of the application to set as command string.
	if (!GetModuleFileName(NULL, exePath, MAX_PATH))
	{
		RegCloseKey(key);
		return FALSE;
	}

	RegCloseKey(key);

	// Check if the value of the key is the same as the working directory of the current CrySearch instance.
	return StrRStrI(regKey, NULL, exePath) ? TRUE : FALSE;
}