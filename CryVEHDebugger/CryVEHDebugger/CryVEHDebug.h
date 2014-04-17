#include <Windows.h>

#define COMM_MAPPING_SIZE 65536 // 64 kb size of the communications shared memory.

// Represents the header for the VEH debugger communications channel.
// It should be mapped at the base address of the memory mapped file and used to navigate further into the data.
typedef struct _CRY_VEH_COMMUNICATION_HEADER
{
	BOOL BreakpointWasHit;
	SIZE_T ExceptionAddress;
	CONTEXT ThreadContext;
} CRY_VEH_COMMUNICATION_HEADER;