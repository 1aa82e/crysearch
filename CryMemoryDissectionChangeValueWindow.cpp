#include "CryMemoryDissectionChangeValueWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

CryMemoryDissectionChangeValueWindow::CryMemoryDissectionChangeValueWindow(SIZE_T address, CCryDataType rowType, int* size) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
{
	this->address = address;
	this->rowType = rowType;
	this->size = size;
	
	this->Title("Change Value").SetRect(0, 0, 250, 120);

	this->mCancel <<= THISBACK(CancelDialog);
	this->mOk <<= THISBACK(DialogOkay);
	
	*this
		<< this->mCancel.SetLabel("Cancel").HSizePos(190, 5).BottomPos(5, 25)
		<< this->mOk.Ok().SetLabel("OK").HSizePos(130, 60).BottomPos(5, 25)
		<< this->mFieldDescription.SetLabel("Value:").HSizePos(5, 100).TopPos(5, 20)
		<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 20)
	;
	
	if (this->rowType == CRYDATATYPE_BYTE || this->rowType == CRYDATATYPE_2BYTES ||
		this->rowType == CRYDATATYPE_4BYTES || this->rowType == CRYDATATYPE_8BYTES)
	{
		*this << this->mValueIsHex.SetLabel("Hexadecimal").HSizePos(5, 100).TopPos(30, 20);
		this->mValueIsHex.WhenAction = THISBACK(ValueModeHexOptionChanged);
	}
	
	// Read and format existing value from memory for display inside the input field.
	if (this->rowType == CRYDATATYPE_BYTE)
	{
		Byte value;
		mMemoryScanner->Peek(this->address, 0, &value);
		char text[64];
		sprintf_s(text, 64, "%hhi", value);
		this->mFieldValue.SetText(text);
	}
	else if (this->rowType == CRYDATATYPE_2BYTES)
	{
		short value;
		mMemoryScanner->Peek(this->address, 0, &value);
		char text[64];
		sprintf_s(text, 64, "%hi", value);
		this->mFieldValue.SetText(text);
	}
	else if (this->rowType == CRYDATATYPE_4BYTES)
	{
		int value;
		mMemoryScanner->Peek(this->address, 0, &value);
		this->mFieldValue.SetText(Format("%li", value));
	}
	else if (this->rowType == CRYDATATYPE_8BYTES)
	{
		__int64 value;
		mMemoryScanner->Peek(this->address, 0, &value);
		this->mFieldValue.SetText(Format("%lli", value));
	}
	else if (this->rowType == CRYDATATYPE_FLOAT)
	{
		float value;
		mMemoryScanner->Peek(this->address, 0, &value);
		this->mFieldValue.SetText(DblStr(value));
	}
	else if (this->rowType == CRYDATATYPE_DOUBLE)
	{
		double value;
		mMemoryScanner->Peek(this->address, 0, &value);
		this->mFieldValue.SetText(DblStr(value));
	}
	else if (this->rowType == CRYDATATYPE_AOB)
	{
		ArrayOfBytes value;
		mMemoryScanner->Peek(this->address, *this->size, &value);
		this->mFieldValue.SetText(BytesToString(value.Data, value.Size));
	}	
	else if (this->rowType == CRYDATATYPE_STRING)
	{
		String value;
		mMemoryScanner->Peek(this->address, *this->size, &value);
		this->mFieldValue.SetText(value);
	}
	else if (this->rowType == CRYDATATYPE_WSTRING)
	{
		WString value;
		mMemoryScanner->Peek(this->address, *this->size, &value);
		this->mFieldValue.SetText(value.ToString());
	}
}

CryMemoryDissectionChangeValueWindow::~CryMemoryDissectionChangeValueWindow()
{
	
}

void CryMemoryDissectionChangeValueWindow::ValueModeHexOptionChanged()
{
	if (this->mValueIsHex)
	{
		if (this->rowType == CRYDATATYPE_8BYTES)
		{
			__int64 v = ScanInt64(this->mFieldValue.GetText().ToString());
			this->mFieldValue.SetText(FormatInt64HexUpper(v));
		}
		else if (this->rowType == CRYDATATYPE_4BYTES)
		{
			int v = ScanInt(this->mFieldValue.GetText().ToString());
			this->mFieldValue.SetText(FormatHexadecimalIntSpecial(v));
		}
		else if (this->rowType == CRYDATATYPE_2BYTES)
		{
			short v = ScanInt(this->mFieldValue.GetText().ToString());
			char text[64];
			sprintf_s(text, 64, "%hX", v);
			this->mFieldValue.SetText(text);	
		}
		else if (this->rowType == CRYDATATYPE_BYTE)
		{
			Byte v = ScanInt(this->mFieldValue.GetText().ToString());
			char text[64];
			sprintf_s(text, 64, "%hhX", v);
			this->mFieldValue.SetText(text);
		}
	}
	else
	{
		if (this->rowType == CRYDATATYPE_8BYTES)
		{
			__int64 v = ScanInt64(this->mFieldValue.GetText().ToString(), NULL, 16);
			this->mFieldValue.SetText(Format("%lli", v));
		}
		else if (this->rowType == CRYDATATYPE_4BYTES)
		{
			int v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			this->mFieldValue.SetText(Format("%li", v));
		}
		else if (this->rowType == CRYDATATYPE_2BYTES)
		{
			short v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			char text[64];
			sprintf_s(text, 64, "%hi", v);
			this->mFieldValue.SetText(text);
		}
		else if (this->rowType == CRYDATATYPE_BYTE)
		{
			Byte v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			char text[64];
			sprintf_s(text, 64, "%hhi", v);
			this->mFieldValue.SetText(text);
		}		
	}
}

void CryMemoryDissectionChangeValueWindow::CancelDialog()
{
	this->Close();
}

void CryMemoryDissectionChangeValueWindow::DialogOkay()
{
	// Check for empty input value.
	const String& inputVal = this->mFieldValue.GetText().ToString();
	if (inputVal.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a value.", "OK");
		return;
	}

	// Value is not managed by address table itself, so WPM.
	if (this->rowType == CRYDATATYPE_BYTE)
	{
		if (this->mValueIsHex)
		{
			mMemoryScanner->Poke(this->address, (Byte)ScanInt(inputVal, NULL, 16));
		}
		else
		{
			mMemoryScanner->Poke(this->address, (Byte)ScanInt(inputVal));
		}
	}
	else if (this->rowType == CRYDATATYPE_2BYTES)
	{
		if (this->mValueIsHex)
		{
			mMemoryScanner->Poke(this->address, (short)ScanInt(inputVal, NULL, 16));
		}
		else
		{
			mMemoryScanner->Poke(this->address, (short)ScanInt(inputVal));
		}
	}
	else if (this->rowType == CRYDATATYPE_4BYTES)
	{
		if (this->mValueIsHex)
		{
			mMemoryScanner->Poke(this->address, ScanInt(inputVal, NULL, 16));
		}
		else
		{
			mMemoryScanner->Poke(this->address, ScanInt(inputVal));
		}
	}
	else if (this->rowType == CRYDATATYPE_8BYTES)
	{
		if (this->mValueIsHex)
		{
			mMemoryScanner->Poke(this->address, ScanInt64(inputVal, NULL, 16));
		}
		else
		{
			mMemoryScanner->Poke(this->address, ScanInt64(inputVal));
		}
	}
	else if (this->rowType == CRYDATATYPE_FLOAT)
	{
		mMemoryScanner->Poke(this->address, (float)ScanDouble(inputVal, NULL, true));
	}
	else if (this->rowType == CRYDATATYPE_DOUBLE)
	{
		mMemoryScanner->Poke(this->address, ScanDouble(inputVal, NULL, true));
	}
	else if (this->rowType == CRYDATATYPE_STRING)
	{
		mMemoryScanner->Poke(this->address, inputVal);
		*this->size = this->mFieldValue.GetLength();
	}
	else if (this->rowType == CRYDATATYPE_WSTRING)
	{
		mMemoryScanner->Poke(this->address, this->mFieldValue.GetText());
		*this->size = this->mFieldValue.GetLength();
	}
	else if (this->rowType == CRYDATATYPE_AOB)
	{
		ArrayOfBytes aob = StringToBytes(inputVal);	
		mMemoryScanner->Poke(this->address, aob);
		*this->size = aob.Size;
	}
	
	// Close the form to pass execution back to the main window.
	this->Close();
}