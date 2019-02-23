#ifndef _VirtualDropList_VirtualDropList_h_
#define _VirtualDropList_VirtualDropList_h_

NAMESPACE_UPP

class VirtualPopUpTable : public PopUpTable {
public:
	void Virtual() {
		AddRowNumColumn(String()).Accel();
		NoHeader();
		HeaderTab(0).SetMargin(0);
		MouseMoveCursor();
		NoGrid();
		AutoHideSb();
		SetLineCy(Draw::GetStdFontCy());
		NoPopUpEx();
	}
};

class VirtualDropList : public MultiButton {
protected:
	VirtualPopUpTable list;
	int index;
	int dropwidth;
	const Convert *valueconvert;
	const Display *valuedisplay;
	bool dropfocus;
	bool notnull;
	bool alwaysdrop;
	bool usewheel;
public:
	VirtualDropList();
	~VirtualDropList() { }

	typedef VirtualDropList CLASSNAME;
	typedef MultiButton::Style Style;

	Callback WhenDrop;

	virtual void MouseWheel(Point p, int zdelta, dword keyflags);
	virtual bool Key(dword key, int);

	void Drop();
	void Sync();
	void Cancel();
	void Select();
	void Change(int q);

	void EnableDrop(bool b = true) { MainButton().Enable(b || alwaysdrop); }
	int  GetCount() const          { return list.GetCount(); }
	void SetCount(int c)           { list.SetCount(c); EnableDrop(c > 0 ? true : false); Sync(); }

	void SetData(const Value& data) { SetIndex(data); }
	Value GetData() const           { Value value = GetValue(); return notnull && IsNull(value) ? NotNullError() : value; }
	Value GetValue(int i) const     { return valueconvert->Format(i); }
	Value GetValue() const          { return index < 0 ? Null : GetValue(index); }
	Value operator[](int i) const   { return GetValue(i); }

	void SetIndex(int i);
	int GetIndex() const { return index; }
	void GoBegin()       { if (GetCount()) SetIndex(0); }
	void GoEnd()         { if (GetCount()) SetIndex(GetCount() - 1); }

	const VirtualPopUpTable& GetList() const { return list; }
	VirtualPopUpTable& ListObject()          { return list; }

	VirtualDropList& SetDropLines(int d)                   { list.SetDropLines(d); return *this; }
	VirtualDropList& SetValueConvert(const Convert& cv);
	VirtualDropList& SetConvert(const Convert& cv);
	VirtualDropList& SetDisplay(int i, const Display& d);
	VirtualDropList& SetDisplay(const Display& d);
	VirtualDropList& SetLineCy(int lcy)                    { list.SetLineCy(lcy); return *this; }
	VirtualDropList& SetDisplay(const Display& d, int lcy);
	VirtualDropList& ValueDisplay(const Display& d);
	VirtualDropList& DropFocus(bool b = true)              { dropfocus = b; return *this; }
	VirtualDropList& NoDropFocus()                         { return DropFocus(false); }
	VirtualDropList& AlwaysDrop(bool e = true);
	VirtualDropList& SetStyle(const Style& s)              { MultiButton::SetStyle(s); return *this; }
	VirtualDropList& NotNull(bool b = true)                { notnull = b; return *this; }
	VirtualDropList& DropWidth(int w)                      { dropwidth = w; return *this; }
	VirtualDropList& DropWidthZ(int w)                     { dropwidth = HorzLayoutZoom(w); return *this; }
	VirtualDropList& Wheel(bool b = true)                  { usewheel = b; return *this; }
	VirtualDropList& NoWheel()                             { return Wheel(false); }

	VirtualDropList& SetScrollBarStyle(const ScrollBar::Style& s) { list.SetScrollBarStyle(s); return *this; }
};

END_UPP_NAMESPACE

#endif
