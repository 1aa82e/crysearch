#include "CrySearchWindowManager.h"

CrySearchWindowManager::CrySearchWindowManager()
{
	
}

CrySearchWindowManager::~CrySearchWindowManager()
{
	
}

// ---------------------------------------------------------------------------------------------

// Returns a pointer to the disassembly window.
CryDisasmCtrl* CrySearchWindowManager::GetDisasmWindow()
{
	return &this->mDisasmWindow;
}

// Returns a pointer to the debugger window.
CryDebuggerWindow* CrySearchWindowManager::GetDebuggerWindow()
{
	return &this->mDbgWindow;
}

// Returns a pointer to the imports window.
CryImportsWindow* CrySearchWindowManager::GetImportsWindow()
{
	return &this->mImportsWindow;
}

// Returns a pointer to the PE window.
CryPEWindow* CrySearchWindowManager::GetPEWindow()
{
	return &this->mPEWindow;
}

// Returns a pointer to the module window.
CryModuleWindow* CrySearchWindowManager::GetModuleWindow()
{
	return &this->mModuleList;
}

// Returns a pointer to the threads window.
CryThreadWindow* CrySearchWindowManager::GetThreadWindow()
{
	return &this->mThreadList;
}

// Returns a pointer to the parent window.
CrySearchForm* CrySearchWindowManager::GetParentWindow()
{
	return this->mParentWindow;
}

// ---------------------------------------------------------------------------------------------

// Clears resources of all subwindows at the same time.
void CrySearchWindowManager::ClearWindows()
{
	this->mImportsWindow.ClearList();
	this->mPEWindow.ClearList();
	this->mThreadList.ClearList();
	this->mModuleList.ClearList();
	this->mDisasmWindow.ClearList();
	this->mDbgWindow.Cleanup();
}

// Sets the parent window of the window manager instance.
void CrySearchWindowManager::SetParentWindow(CrySearchForm* pParent)
{
	this->mParentWindow = pParent;
}