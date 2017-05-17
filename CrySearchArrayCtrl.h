#ifndef _CrySearch_CrySearchArrayCtrl_h_
#define _CrySearch_CrySearchArrayCtrl_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents a customized ArrayCtrl to fit CrySearch user interface needs.
class CrySearchArrayCtrl : public ArrayCtrl
{
private:
	virtual bool Key(dword key, int count);
public:
	ArrayCtrl::Column& CryAddColumn(const char *text = NULL, int w = 0);
	ArrayCtrl::Column& CryAddRowNumColumn(const char *text, int w = 0);
	
	// Must be implemented by the owner of the control in order to be able to remove items using
	// this routine. This only works for controls with virtual rows. The caller must refresh the
	// control to finish the removal operation.
	Callback1<const Vector<int>&> RemovalRoutine;
};

#endif