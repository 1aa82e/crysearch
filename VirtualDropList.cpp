#include <CtrlLib/CtrlLib.h>
#include "VirtualDropList.h"

NAMESPACE_UPP

VirtualDropList::VirtualDropList() : index(-1), valueconvert(&NoConvert()), valuedisplay(NULL),
	dropfocus(false), notnull(false), alwaysdrop(false), dropwidth(0), usewheel(true)
{
	AddButton().Main().WhenPush = THISBACK(Drop);
	NoInitFocus();
	EnableDrop(false);
	list.Virtual();
	list.WhenCancel = THISBACK(Cancel);
	list.WhenSelect = THISBACK(Select);
}

void VirtualDropList::MouseWheel(Point p, int zdelta, dword keyflags)
{
	if (usewheel)
		Change(zdelta < 0 ? 1 : -1);
}

bool VirtualDropList::Key(dword key, int)
{
	if (IsReadOnly())
		return false;
	switch(key) {
	case K_ALT_DOWN:
		Drop();
		break;
	case K_DOWN:
	case K_RIGHT:
		Change(1);
		break;
	case K_UP:
	case K_LEFT:
		Change(-1);
		break;
	default:
		if (key >= 32 && key < 65536) {
			bool b = list.Key(key, 1);
			int c = list.GetCursor();
			if (c >= 0 && c < list.GetCount())
				Select();
			return b;
		}
		return false;
	}
	return true;
}

void VirtualDropList::Drop()
{
	if (IsReadOnly())
		return;
	if(dropfocus)
		SetFocus();
	WhenDrop();
	list.SetCursor(index);
	list.PopUp(this, dropwidth);
}

void VirtualDropList::Sync() {
	const Display& d = valuedisplay ? *valuedisplay : index >= 0 ? list.GetDisplay(index, 0)
	                                                         : list.GetDisplay(0);
	MultiButton::SetDisplay(d);
	MultiButton::SetValueCy(list.GetLineCy());
	if (index >= 0)
		Set(valueconvert->Format(index));
}

void VirtualDropList::Cancel()
{
	if (dropfocus)
		SetFocus();
	Sync();
}

void VirtualDropList::Select()
{
	int c = list.GetCursor();
	if (c >= 0)
		index = c;
	if (dropfocus)
		SetFocus();
	Sync();
	UpdateAction();
}

void VirtualDropList::Change(int q)
{
	int count = list.GetCount();
	if (count == 0)
		return;
	int c = index + q;
	if (c < 0)
		c = 0;
	else if (c >= count)
		c = count - 1;
	SetIndex(c);
}

void VirtualDropList::SetIndex(int i)
{
	if (i == index)
		return;
	index = i;
	Update();
	Sync();
}

VirtualDropList& VirtualDropList::SetValueConvert(const Convert& cv)
{
	valueconvert = &cv;
	Sync();
	return *this;
}

VirtualDropList& VirtualDropList::SetConvert(const Convert& cv)
{
	list.ColumnAt(0).SetConvert(cv);
	return SetValueConvert(cv);
}

VirtualDropList& VirtualDropList::SetDisplay(int i, const Display& d)
{
	list.SetDisplay(i, 0, d);
	Sync();
	return *this;
}

VirtualDropList& VirtualDropList::SetDisplay(const Display& d)
{
	list.ColumnAt(0).SetDisplay(d);
	Sync();
	return *this;
}

VirtualDropList& VirtualDropList::SetDisplay(const Display& d, int lcy)
{
	SetDisplay(d);
	SetLineCy(lcy);
	Sync();
	return *this;
}

VirtualDropList& VirtualDropList::ValueDisplay(const Display& d)
{
	valuedisplay = &d;
	Sync();
	return *this;
}

VirtualDropList& VirtualDropList::AlwaysDrop(bool e)
{
	alwaysdrop = e;
	if (e)
		EnableDrop();
	return *this;
}

END_UPP_NAMESPACE
