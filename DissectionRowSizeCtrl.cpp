#include "DissectionRowSizeCtrl.h"

DissectionRowSizeCtrl::DissectionRowSizeCtrl()
{
	*this
		<< this->mDescriptor.SetLabel("Length:").LeftPos(0, 40).TopPos(5)
		<< this->mCurrentRowDataSize.Min(1).HSizePos(45, 5).TopPos(0)
	;
	
	this->mCurrentRowDataSize.WhenAction = THISBACK(ValueEntered);
}

DissectionRowSizeCtrl::~DissectionRowSizeCtrl()
{
	
}

// Executed when the value inside the internal editable control changes.
void DissectionRowSizeCtrl::ValueEntered()
{
	this->WhenValueSet(this->mCurrentRowDataSize);
}

// Sets the value of the internal editable control.
void DissectionRowSizeCtrl::SetValueInt(const int value)
{
	this->mCurrentRowDataSize.SetData(value);
}