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

CryClickLabel& CryClickLabel::SetLabel(const char* lbl)
{
	this->mLinkLabel.SetLabel(lbl);
	return *this;
}

void CryClickLabel::SetTooltip(const char* tt)
{
	this->mLinkLabel.Info(tt);
}

CryClickLabel& CryClickLabel::SetColor(Color color)
{
	this->mLinkLabel.SetInk(color);
	return *this;
}

void CryClickLabel::Clear()
{
	this->mLinkLabel.SetLabel("");
}