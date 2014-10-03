#ifndef _CrySearch_CryDialogTemplate_h_
#define _CrySearch_CryDialogTemplate_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Template dialog that closes on ESC. I keep forgetting this so...
// This template also forces the developer to pass an icon to each inherited component.
// In case the default icon should be used, pass the default icon. This way you can't forget to
// pass an icon, making components having default (maybe no logical) icons.
class CryDialogTemplate : public TopWindow
{
private:
	virtual bool Key(dword key, int count)
	{
		// Check for ESC key presses.
		if (key == K_ESCAPE)
		{
			this->Close();
			return true;
		}
		
		// Execute base key function of the TopWindow class.
		return TopWindow::Key(key, count);
	};
public:
	CryDialogTemplate(const Image& icon)
	{
		this->Icon(icon);
	};
	
	virtual ~CryDialogTemplate() { }
};

#endif