#include <Windows.h>

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = dest;
	const char *s2 = src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}