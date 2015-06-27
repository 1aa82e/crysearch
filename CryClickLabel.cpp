#include "CryClickLabel.h"

CryClickLabel::CryClickLabel()
{
	*this << this->mLinkLabel.SizePos();
}

CryClickLabel::~CryClickLabel()
{
	
}

Image CryClickLabel::CursorImage(Point p, dword keyflags)
{
	return Image::Hand();
}

void CryClickLabel::LeftUp(Point p, dword keyflags)
{
	this->WhenLeftUp();
}

// Sets the text displayed by the label to the string pointer to by 'lbl'.
CryClickLabel& CryClickLabel::SetLabel(const char* lbl)
{
	this->mLinkLabel.SetLabel(lbl);
	return *this;
}

// Sets a tooltip to display.
void CryClickLabel::SetTooltip(const char* tt)
{
	this->mLinkLabel.Info(tt);
}

// Sets the color of the text displayed inside the label.
CryClickLabel& CryClickLabel::SetColor(Color color)
{
	this->mLinkLabel.SetInk(color);
	return *this;
}

// Clears the text inside the label.
void CryClickLabel::Clear()
{
	this->mLinkLabel.SetLabel("");
}