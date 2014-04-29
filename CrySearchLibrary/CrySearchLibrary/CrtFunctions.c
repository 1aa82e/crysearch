#include <Windows.h>

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = (char*)dest;
	const char *s2 = (char*)src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}

// Custom implementation of strlen to avoid linking to CRT.
#pragma function(strlen)
size_t strlen(const char* s)
{
	const char* p = s;
	while(*++p);
	return p - s;
}