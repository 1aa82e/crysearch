#ifndef _CrySearch_HIconToImage_h_
#define _CrySearch_HIconToImage_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// These functions support the icon retrieval functionality inside the process selection window.
HICON hIconFromWindow(HWND hWindow);
BOOL __stdcall enumProc(HWND hwnd, LPARAM lParam);
HICON hIconForPID(DWORD pID);
Image CreateImageFromHICON(HICON icon);

#endif