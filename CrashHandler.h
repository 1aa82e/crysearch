#ifndef _CrySearch_CrashHandler_h_
#define _CrySearch_CrashHandler_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class CryCrashHandlerWindow sealed : public TopWindow
{
private:
	ImageCtrl mErrorImage;
	Label mDescriptionLabel;
	LineEdit mCrashReport;
	Button mOk;
	Button mCopyToClipboard;
	
	typedef CryCrashHandlerWindow CLASSNAME;
	
	void CopyCrashReport();
	void CloseWindow();
public:
	CryCrashHandlerWindow(const String& excMsg);
	~CryCrashHandlerWindow();
};

// Global application crash handler function.
extern "C" LONG __stdcall CrashHandler(PEXCEPTION_POINTERS ExceptionInfo);

// The CrySearch debugger also needs this information.
const char* ParseExceptionCode(LONG excCode);

#endif