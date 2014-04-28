#ifndef _CrySearch_CryDialogTemplate_h_
#define _CrySearch_CryDialogTemplate_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Template dialog that closes on ESC. I keep forgetting this so...
class CryDialogTemplate : public TopWindow
{
private:
	virtual bool Key(dword key, int count)
	{
		if (key == K_ESCAPE)
		{
			this->Close();
			return true;
		}
		
		return false;
	};
public:
	CryDialogTemplate() { }
	virtual ~CryDialogTemplate() { }
};

#endif