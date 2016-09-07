#include "../SDK/UtilFunctions.h"

// Represents a lookup table entry for the handle permission lookup.
typedef struct _PERMISSIONLINKAGE
{
	DWORD Permission;
	char* StringRepresentation;
} PERMISSIONLINKAGE, *PPERMISSIONLINKAGE;

// Contains possible file access rights linked to their string representation.
PERMISSIONLINKAGE FilePermissionLookup[] =
{
	{ GENERIC_READ, "GENERIC_READ" },
	{ GENERIC_EXECUTE, "GENERIC_EXECUTE" },
	{ GENERIC_WRITE, "GENERIC_WRITE" },
	{ FILE_ADD_FILE, "FILE_ADD_FILE" },
	{ FILE_ADD_SUBDIRECTORY, "FILE_ADD_SUBDIRECTORY" },
	{ FILE_APPEND_DATA, "FILE_APPEND_DATA" },
	{ FILE_CREATE_PIPE_INSTANCE, "FILE_CREATE_PIPE_INSTANCE" },
	{ FILE_DELETE_CHILD, "FILE_DELETE_CHILD" },
	{ FILE_EXECUTE, "FILE_EXECUTE" },
	{ FILE_LIST_DIRECTORY, "FILE_LIST_DIRECTORY" },
	{ FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES" },
	{ FILE_READ_DATA, "FILE_READ_DATA" },
	{ FILE_READ_EA, "FILE_READ_EA" },
	{ FILE_TRAVERSE, "FILE_TRAVERSE" },
	{ FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES" },
	{ FILE_WRITE_DATA, "FILE_WRITE_DATA" },
	{ FILE_WRITE_EA, "FILE_WRITE_EA" }
};

// Contains possible thread access rights linked to their string representation.
PERMISSIONLINKAGE ThreadPermissionLookup[] =
{
	{ SYNCHRONIZE, "SYNCHRONIZE" },
	{ THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION" },
	{ THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT" },
	{ THREAD_IMPERSONATE, "THREAD_IMPERSONATE" },
	{ THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION" },
	{ THREAD_QUERY_LIMITED_INFORMATION, "THREAD_QUERY_LIMITED_INFORMATION" },
	{ THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT" },
	{ THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION" },
	{ THREAD_SET_LIMITED_INFORMATION, "THREAD_SET_LIMITED_INFORMATION" },
	{ THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN" },
	{ THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME" },
	{ THREAD_TERMINATE, "THREAD_TERMINATE" }
};

// Contains possible process access rights linked to their string representation.
PERMISSIONLINKAGE ProcessPermissionLookup[] =
{
	{ PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS" },
	{ PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD" },
	{ PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE" },
	{ PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION" },
	{ PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION" },
	{ PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION" },
	{ PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA" },
	{ PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME" },
	{ PROCESS_TERMINATE, "PROCESS_TERMINATE" },
	{ PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION" },
	{ PROCESS_VM_READ, "PROCESS_VM_READ" },
	{ PROCESS_VM_WRITE, "PROCESS_VM_WRITE" },
	{ SYNCHRONIZE, "SYNCHRONIZE" }
};

// Contains possible registry key access rights linked to their string representation.
PERMISSIONLINKAGE RegistryKeyPermissionsLookup[] =
{
	{ KEY_CREATE_LINK, "KEY_CREATE_LINK" },
	{ KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY" },
	{ KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS" },
	{ KEY_EXECUTE, "KEY_EXECUTE" },
	{ KEY_NOTIFY, "KEY_NOTIFY" },
	{ KEY_QUERY_VALUE, "KEY_QUERY_VALUE" },
	{ KEY_READ, "KEY_READ" },
	{ KEY_SET_VALUE, "KEY_SET_VALUE" },
	{ KEY_WOW64_32KEY, "KEY_WOW64_32KEY" },
	{ KEY_WOW64_64KEY, "KEY_WOW64_64KEY" },
	{ KEY_WRITE, "KEY_WRITE" }
};

// Parses an access mask value and returns the strings of the access constants it incoorporates.
// The caller must specify a buffer and is responsible for its allocation and deletion. The recommended
// size for the 'outBuffer' parameter depends on the type of handle. The size constants per type are defined above.
void GetHandleObjectAccess(const DWORD type, const DWORD mask, char** const outBuffer, DWORD* const outSize)
{
	PPERMISSIONLINKAGE ltPointer = NULL;
	DWORD arrSize = 0;

	// Validate the buffer first.
	if (!outBuffer)
	{
		return;
	}
	
	// Determine the type of access mask that is being queried.
	switch (type)
	{
		case HANDLE_ACCESS_TYPE_FILE:
			ltPointer = FilePermissionLookup;
			arrSize = _countof(FilePermissionLookup);
			break;
		case HANDLE_ACCESS_TYPE_THREAD:
			ltPointer = ThreadPermissionLookup;
			arrSize = _countof(ThreadPermissionLookup);
			break;
		case HANDLE_ACCESS_TYPE_PROCESS:
			ltPointer = ProcessPermissionLookup;
			arrSize = _countof(ProcessPermissionLookup);
			break;
		case HANDLE_ACCESS_TYPE_REGKEY:
			ltPointer = RegistryKeyPermissionsLookup;
			arrSize = _countof(RegistryKeyPermissionsLookup);
			break;
	}
	
	// Sanity checking, is a proper type found.
	if (ltPointer)
	{
		DWORD i = 0;
		DWORD j = 0;
		while (i < arrSize)
		{
			// Check if mask inherites access constant.
			if (mask & ltPointer[i].Permission)
			{
				outBuffer[j++] = ltPointer[i].StringRepresentation;
			}
			
			++i;
		}
		
		*outSize = j;
	}
}