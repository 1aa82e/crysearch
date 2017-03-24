#include "HIconToImage.h"

#define HICON_MESSAGE_TIMEOUT 100

// The process window may have been closed during a timeout operation. Kill operation after timeout using this variable.
extern bool ProcWndClosed;

// All kinds of window messages can be used to get an icon. This function uses them all.
// If you want high-quality icons, first use ICON_BIG, then ICON_SMALL2, ICON_SMALL, GCL_HICON, GCL_HICONSM, WM_QUERYDRAGICON.
// For high-quality icons, CreateImageFromHICON should use 32.
HICON hIconFromWindow(HWND hWindow)
{
	DWORD_PTR hIcon = NULL;
	SendMessageTimeout(hWindow, WM_GETICON, ICON_SMALL2, 0, SMTO_ABORTIFHUNG, HICON_MESSAGE_TIMEOUT, &hIcon);
	if(!ProcWndClosed && !hIcon)
	{
		SendMessageTimeout(hWindow, WM_GETICON, ICON_SMALL, 0, SMTO_ABORTIFHUNG, HICON_MESSAGE_TIMEOUT, &hIcon);
		if(!ProcWndClosed && !hIcon)
		{
			SendMessageTimeout(hWindow, WM_GETICON, ICON_BIG, 0, SMTO_ABORTIFHUNG, HICON_MESSAGE_TIMEOUT, &hIcon);
			if(!ProcWndClosed && !hIcon)
			{
				hIcon = GetClassLongPtr(hWindow, GCLP_HICONSM); // Constant for x64 is different from example.
				if(!ProcWndClosed && !hIcon)
				{
					hIcon = GetClassLongPtr(hWindow, GCLP_HICON); // Constant for x64 is different from example.
					if(!ProcWndClosed && !hIcon)
					{
						SendMessageTimeout(hWindow, WM_QUERYDRAGICON, ICON_BIG, 0, SMTO_NORMAL, HICON_MESSAGE_TIMEOUT, &hIcon);
					}
				}
			}
		}
	}
	
	return (HICON)hIcon;
}

// Window enum procedure that attempts to get the icon handle for the main window of the process.
BOOL __stdcall enumProc(HWND hwnd, LPARAM lParam)
{
	SIZE_T* args = (SIZE_T*)lParam;
	DWORD pID = 0;
	GetWindowThreadProcessId(hwnd, &pID);
	
	if(pID == args[0] && (args[1] = (SIZE_T)hIconFromWindow(hwnd)))
	{
		return FALSE;
	}

	return TRUE;
}

// Starts window enumeration for a process.
// Returns the handle to the icon associated with the window. returns NULL if it failed.
HICON hIconForPID(DWORD pID)
{
	SIZE_T args[2] = {pID, 0};
	EnumWindows(enumProc, (LPARAM)args);
	return (HICON)args[1];
}

// Get data from the icon handle from Win32 and create an image from it.
// Returns an empty image if there is no icon associated.
Image CreateImageFromHICON(HICON icon)
{
	// Did we get an icon back?
	if(!icon)
	{
		// The associated process did not have a main window with an icon, create blank one.
		ImageBuffer imgb(16, 16);
		memset(imgb.Begin(), 0, imgb.GetLength() * sizeof(RGBA));
		return Image(imgb);
	}
	
	// We got an icon back. Read it and process it.
	HDC hDC = GetDC(NULL);
	HDC hMemDC = CreateCompatibleDC(hDC);
	HBITMAP hBM = CreateCompatibleBitmap(hDC, 16, 16);
	HGDIOBJ hOldBM = SelectObject(hMemDC, hBM);
	
	// Draw icon onto memory device context and create a bitmap using this as source.
	PatBlt(hMemDC, 0, 0, 16, 16, WHITENESS);
	DrawIconEx(hMemDC, 0, 0, icon, 16, 16, 0, 0, DI_NORMAL | DI_COMPAT);
	
	BITMAP bmScreen = {NULL};
	GetObject(hBM, sizeof(bmScreen), &bmScreen);
	BITMAPINFOHEADER bi =  { sizeof(bi), NULL };
	bi.biWidth = bmScreen.bmWidth;
	bi.biHeight = bmScreen.bmHeight;
	bi.biPlanes = 1;
	bi.biBitCount = 32;
	bi.biCompression = BI_RGB;

	DWORD dwScan = ((bmScreen.bmWidth * bi.biBitCount + 31) / 32);
	DWORD dwBmpSize = dwScan * sizeof(RGBA) * bmScreen.bmHeight;
	bi.biSizeImage = dwBmpSize;

	HANDLE hDIB = GlobalAlloc(GHND, dwBmpSize);
	Byte* const lpbitmap = (Byte*)GlobalLock(hDIB);
	GetDIBits(hDC, hBM, 0, (UINT)bmScreen.bmHeight, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

	// These loops are hard to analyse for the compiler, so I added the __restrict qualifier to
	// the pointers it uses. This way, the compiler could analyse them, because it could
	// guarantee that lpY and bufY do not overlap. Vectorization was still unprofitable though.
	ImageBuffer imgb(16, 16);
	for(int y = 0; y < 16; ++y)
	{
		const Byte* __restrict const lpY = lpbitmap + dwScan * sizeof(RGBA) * y;
		RGBA* __restrict const bufY = imgb[15 - y];
		for(int x = 0; x < 16; ++x)
		{
			bufY[x].r = lpY[x * sizeof(RGBA) + 2];
			bufY[x].g = lpY[x * sizeof(RGBA) + 1];
			bufY[x].b = lpY[x * sizeof(RGBA) + 0];
			bufY[x].a = 255;
		}
	}
	
	// Free used resources.
	GlobalUnlock(hDIB);
	GlobalFree(hDIB);
	SelectObject(hMemDC, hOldBM);
	DeleteObject(hBM);
	DeleteDC(hMemDC);
	ReleaseDC(NULL, hDC);
	return Image(imgb);
}