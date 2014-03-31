#ifndef _CrySearch_HyperLinkLabel_h_
#define _CrySearch_HyperLinkLabel_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents a label that is clickable, for example, to execute a hyperlink.
class CryClickLabel : public ParentCtrl
{
private:
	Label mLinkLabel;
	
	virtual Image CursorImage(Point p, dword keyflags);
	virtual void LeftUp(Point p, dword keyflags);
public:
	CryClickLabel();
	~CryClickLabel();

	Callback WhenLeftUp;
	
	CryClickLabel& SetLabel(const char* lbl);
	void SetTooltip(const char* tt);
	CryClickLabel& SetColor(Color color);
	
	void Clear();
};

#endif
