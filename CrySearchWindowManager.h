#ifndef _CrySearch_CrySearchWindowManager_h_
#define _CrySearch_CrySearchWindowManager_h_

#include "CryThreadWindow.h"
#include "CryModuleWindow.h"
#include "CryPEWindow.h"
#include "CryImportsWindow.h"
#include "CryDebuggerWindow.h"
#include "CryDisasmCtrl.h"

// Forward declaration of CrySearchForm class type, to allow parent pointer to be declared.
class CrySearchForm;

// Data structure used to proxy data through dispatched callbacks.
template <class T>
struct AsynchronousDispatchable
{
	T Data;
	volatile Atomic Indicator;
};

// Represents the window manager that CrySearchForm uses to proxy its subwindows to the application backend.
class CrySearchWindowManager
{
private:
	CrySearchForm* mParentWindow;
	
	CryThreadWindow mThreadList;
	CryModuleWindow mModuleList;
	CryPEWindow mPEWindow;
	CryImportsWindow mImportsWindow;
	CryDisasmCtrl mDisasmWindow;
	CryDebuggerWindow mDbgWindow;
public:
	CrySearchWindowManager();
	~CrySearchWindowManager();

	CryDisasmCtrl* GetDisasmWindow();
	CryDebuggerWindow* GetDebuggerWindow();
	CryImportsWindow* GetImportsWindow();
	CryPEWindow* GetPEWindow();
	CryModuleWindow* GetModuleWindow();
	CryThreadWindow* GetThreadWindow();
	CrySearchForm* GetParentWindow();
	
	void ClearWindows();
	void SetParentWindow(CrySearchForm* pParent);
	
	template <class T>
	void RegisterMainWindowDispatchable(const Callback1<T>& cb);
	void ExecuteCrashHandlerWindow(const String& msg);
};

#endif