#ifndef _CrySearch_DissectionRowSizeCtrl_h_
#define _CrySearch_DissectionRowSizeCtrl_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents a size parameter control that can be set in a menu bar.
class DissectionRowSizeCtrl : public ParentCtrl
{
private:
	Label mDescriptor;
	EditIntNotNullSpin mCurrentRowDataSize;
	
	void ValueEntered();
	
	typedef DissectionRowSizeCtrl CLASSNAME;
public:
	DissectionRowSizeCtrl();
	~DissectionRowSizeCtrl();
	
	Callback1<int> WhenValueSet;
	
	void SetValueInt(const int value);
};

#endif