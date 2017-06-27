#include "CryMemoryDissectionChangeValueWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

// CryMemoryDissectionChangeValueWindow default constructor.
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
		<< this->mFieldDescription.SetLabel("Value:").HSizePos(5, 100).TopPos(5, 25)
		<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 25)
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
		mMemoryScanner->Peek(this->address, sizeof(Byte), &value);
		this->mFieldValue.SetText(FormatIntSpecial(value));
	}
	else if (this->rowType == CRYDATATYPE_2BYTES)
	{
		short value;
		mMemoryScanner->Peek(this->address, sizeof(short), &value);
		this->mFieldValue.SetText(FormatIntSpecial(value));
	}
	else if (this->rowType == CRYDATATYPE_4BYTES)
	{
		int value;
		mMemoryScanner->Peek(this->address, sizeof(int), &value);
		this->mFieldValue.SetText(FormatIntSpecial(value));
	}
	else if (this->rowType == CRYDATATYPE_8BYTES)
	{
		__int64 value;
		mMemoryScanner->Peek(this->address, sizeof(__int64), &value);
		this->mFieldValue.SetText(FormatIntSpecial64(value));
	}
	else if (this->rowType == CRYDATATYPE_FLOAT)
	{
		float value;
		mMemoryScanner->Peek(this->address, sizeof(float), &value);
		this->mFieldValue.SetText(DblStr(value));
	}
	else if (this->rowType == CRYDATATYPE_DOUBLE)
	{
		double value;
		mMemoryScanner->Peek(this->address, sizeof(double), &value);
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

// CryMemoryDissectionChangeValueWindow default destructor.
CryMemoryDissectionChangeValueWindow::~CryMemoryDissectionChangeValueWindow()
{
	
}

// Executed when the view mode is changed from or to hexadecimal mode.
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
			sprintf_s(text, 64, "%hhu", v);
			this->mFieldValue.SetText(text);
		}
	}
}

// Closes the dialog without saving anything.
void CryMemoryDissectionChangeValueWindow::CancelDialog()
{
	this->Close();
}

// Executed when the user accepts the dialog.
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
		const Byte value = this->mValueIsHex ? ScanInt(inputVal, NULL, 16) : ScanInt(inputVal);
		mMemoryScanner->Poke(this->address, &value, sizeof(Byte));
	}
	else if (this->rowType == CRYDATATYPE_2BYTES)
	{
		const short value = this->mValueIsHex ? ScanInt(inputVal, NULL, 16) : ScanInt(inputVal);
		mMemoryScanner->Poke(this->address, &value, sizeof(short));
	}
	else if (this->rowType == CRYDATATYPE_4BYTES)
	{
		const int value = this->mValueIsHex ? ScanInt(inputVal, NULL, 16) : ScanInt(inputVal);
		mMemoryScanner->Poke(this->address, &value, sizeof(int));
	}
	else if (this->rowType == CRYDATATYPE_8BYTES)
	{
		const __int64 value = this->mValueIsHex ? ScanInt64(inputVal, NULL, 16) : ScanInt64(inputVal);
		mMemoryScanner->Poke(this->address, &value, sizeof(__int64));
	}
	else if (this->rowType == CRYDATATYPE_FLOAT)
	{
		const float value = (float)ScanDouble(inputVal, NULL, true);
		mMemoryScanner->Poke(this->address, &value, sizeof(float));
	}
	else if (this->rowType == CRYDATATYPE_DOUBLE)
	{
		const double value = ScanDouble(inputVal, NULL, true);
		mMemoryScanner->Poke(this->address, &value, sizeof(double));
	}
	else if (this->rowType == CRYDATATYPE_STRING)
	{
		mMemoryScanner->PokeA(this->address, inputVal);
		*this->size = this->mFieldValue.GetLength();
	}
	else if (this->rowType == CRYDATATYPE_WSTRING)
	{
		mMemoryScanner->PokeW(this->address, this->mFieldValue.GetText());
		*this->size = this->mFieldValue.GetLength();
	}
	else if (this->rowType == CRYDATATYPE_AOB)
	{
		ArrayOfBytes aob = StringToBytes(inputVal);
		mMemoryScanner->PokeB(this->address, aob);
		*this->size = aob.Size;
	}
	
	// Close the form to pass execution back to the main window.
	this->Close();
}