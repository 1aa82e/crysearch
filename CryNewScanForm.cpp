#include "CryNewScanForm.h"
#include "UIUtilities.h"
#include "SettingsFile.h"

// Describes a memory scanner scan type, bound to a string representation.
struct ScanTypeDescriptor
{
	MemoryScanType ScanType;
	String StringRepresentation;
};

// The scan type descriptor table.
ScanTypeDescriptor ScanTypeDescriptorDescriptorTable[] =
{
	{ SCANTYPE_UNKNOWN_INITIAL_VALUE, "Unknown Initial Value" },
	{ SCANTYPE_EXACTVALUE, "Exact Value" },
	{ SCANTYPE_SMALLERTHAN, "Smaller Than" },
	{ SCANTYPE_GREATERTHAN, "Greater Than" },
	{ SCANTYPE_VALUE_IN_BETWEEN, "Value Between" },
	{ SCANTYPE_CHANGED, "Changed Value" },
	{ SCANTYPE_UNCHANGED, "Unchanged Value" },
	{ SCANTYPE_INCREASED, "Increased Value" },
	{ SCANTYPE_DECREASED, "Decreased Value" }
};

// Retrieves the correct scan type enumeration value from a string representation input.
// Returns -1 if the correct value is not found in debug mode, otherwise it returns SCANTYPE_UNKNOWN_INITIAL_VALUE.
MemoryScanType GetMemoryScanTypeFromStringRepresentation(const String& strRep)
{
	for (unsigned int i = 0; i < _countof(ScanTypeDescriptorDescriptorTable); ++i)
	{
		if (ScanTypeDescriptorDescriptorTable[i].StringRepresentation == strRep)
		{
			return ScanTypeDescriptorDescriptorTable[i].ScanType;
		}
	}
	
#ifdef _DEBUG
	return (MemoryScanType)-1;
#else
	return SCANTYPE_UNKNOWN_INITIAL_VALUE;
#endif
}

// ---------------------------------------------------------------------------------------------

// CryNewScanForm default constructor.
CryNewScanForm::CryNewScanForm(bool FirstScan, const Image& icon) : CryDialogTemplate(icon)
{
	this->mNextScan = !FirstScan;
	
	this->Title(FirstScan ? "New Scan" : "Next Scan").SetRect(0, 0, 275, 185);
	
	this->mOk <<= THISBACK(OkButtonClicked);
	this->Rejector(this->mCancel, IDCANCEL);
	
	*this
		<< this->mValueInfoLabel.SetLabel("Value:").LeftPos(5, 75).TopPos(5, 25)
		<< this->mValueIsHex.SetLabel("Hex").LeftPos(75, 50).TopPos(5, 25)
		<< this->mValueToSearchFor.HSizePos(130, 5).TopPos(5, 25)
		<< this->mValueSecondInfoLabel.SetLabel("Second Value:").LeftPos(5, 75).TopPos(35, 25)
		<< this->mSecondValueToSearchFor.HSizePos(130, 5).TopPos(35, 25)
		<< this->mBlockSizeSelectorLabel.SetLabel("Size:").LeftPos(5, 75).TopPos(65, 25)
		<< this->mBlockSizeSelector.Add("Byte").Add("Short (2 Bytes)").Add("Integer (4 Bytes)")
			.Add("Long (8 Bytes)").Add("Float (4 Bytes)").Add("Double (8 Bytes)").Add("Array of Bytes")
			.Add("String (Slower scan, be patient)").HSizePos(75, 5).TopPos(65, 25)
		<< this->mScanTypeSelectorLabel.SetLabel("Type:").LeftPos(5, 75).TopPos(95, 25)
		<< this->mScanTypeSelector.Add("Exact Value").Add("Smaller Than").Add("Greater Than")
			.Add("Value Between").HSizePos(75, 5).TopPos(95, 25)
		<< this->useFastScan.Set(SettingsFile::GetInstance()->GetFastScanByDefault()).SetLabel("Fast Scan")
			.LeftPos(5, 100).BottomPos(35, 25)
		<< this->stringUnicode.SetLabel("Unicode").RightPos(5, 75).BottomPos(35, 25)
		<< this->stringUntilNull.SetLabel("Match until null").HSizePos(80, 80).BottomPos(35, 25)
		<< this->mOk.Ok().SetLabel("OK").RightPos(85, 75).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(5, 75).BottomPos(5, 25)
	;
	
	this->mValueIsHex.WhenAction = THISBACK(ValueInputHexToggleChanged);
	this->mBlockSizeSelector.WhenAction = THISBACK(BlockSizeSelected);
	this->mScanTypeSelector.WhenAction = THISBACK(ScanTypeSelected);
	
	this->mBlockSizeSelectorLabel.Enable(FirstScan);
	this->mBlockSizeSelector.Enable(FirstScan);
	this->useFastScan.Enable(FirstScan);
	this->stringUnicode.Hide();
	this->stringUntilNull.Hide();
	
	// Are we opening the dialog for a first scan or a next scan?
	if (!FirstScan)
	{
		// Add fast scan option.
		this->useFastScan = GlobalScanParameter->CurrentScanFastScan;
		
		// Apply value-type-specific properties.		
		switch(GlobalScanParameter->GlobalScanValueType)
		{
			case CRYDATATYPE_BYTE:
				this->mBlockSizeSelector.SetIndex(0);
				break;
			case CRYDATATYPE_2BYTES:
				this->mBlockSizeSelector.SetIndex(1);
				break;
			case CRYDATATYPE_4BYTES:
				this->mBlockSizeSelector.SetIndex(2);
				break;
			case CRYDATATYPE_8BYTES:
				this->mBlockSizeSelector.SetIndex(3);
				break;
			case CRYDATATYPE_FLOAT:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(4);
				break;
			case CRYDATATYPE_DOUBLE:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(5);
				break;
			case CRYDATATYPE_STRING:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(7);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				break;
			case CRYDATATYPE_WSTRING:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(7);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				this->stringUnicode.Show();
				this->stringUnicode = true;
				this->stringUnicode.Disable();
				break;
			case CRYDATATYPE_AOB:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(6);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				break;
		}
		
		// Add next scan specific scan types to the list of selectable scan types.
		this->mScanTypeSelector.Add("Changed Value");
		this->mScanTypeSelector.Add("Unchanged Value");
		this->mScanTypeSelector.Add("Increased Value");
		this->mScanTypeSelector.Add("Decreased Value");
		
		if (GlobalScanParameter->GlobalScanType == SCANTYPE_CHANGED || GlobalScanParameter->GlobalScanType == SCANTYPE_UNCHANGED
			|| GlobalScanParameter->GlobalScanType == SCANTYPE_INCREASED || GlobalScanParameter->GlobalScanType == SCANTYPE_DECREASED)
		{
			this->mValueInfoLabel.Disable();
			this->mValueToSearchFor.Disable();
			this->mValueSecondInfoLabel.Disable();
			this->mSecondValueToSearchFor.Disable();
		}
		else if (GlobalScanParameter->GlobalScanType != SCANTYPE_VALUE_IN_BETWEEN)
		{
			// Disable the value in between fields if the user did not desire to search so.
			this->mValueSecondInfoLabel.Disable();
			this->mSecondValueToSearchFor.Disable();
		}
		
		this->mBlockSizeSelector.Disable();
		this->mBlockSizeSelectorLabel.Disable();

		MemoryScanType scanType = GlobalScanParameter->GlobalScanType == SCANTYPE_UNKNOWN_INITIAL_VALUE ? (MemoryScanType)0 : (MemoryScanType)(GlobalScanParameter->GlobalScanType - 1);
		this->mScanTypeSelector.SetIndex(scanType);
	}
	else
	{
		this->mScanTypeSelector.Add("Unknown Initial Value");
		
		this->mBlockSizeSelector.SetIndex(2);
		this->mScanTypeSelector.SetIndex(0);
		
		this->mValueSecondInfoLabel.Disable();
		this->mSecondValueToSearchFor.Disable();
	}
}

// CryNewScanForm default destructor.
CryNewScanForm::~CryNewScanForm()
{
	
}

// Executed when the user toggles the hexadecimal/decimal view option.
void CryNewScanForm::ValueInputHexToggleChanged()
{
	const String& curInput = this->mValueToSearchFor.GetText().ToString();
	const String& curSecondInput = this->mSecondValueToSearchFor.GetText().ToString();
	const String& curType = this->mBlockSizeSelector.GetValue();
	
	// Toggle a hexadecimal value representation for the first value field.
	if (!curInput.IsEmpty())
	{
		if (curType != "String (Slower scan, be patient)" && curType != "Array of Bytes" && curType != "Float (4 Bytes)" && curType != "Double (8 Bytes)")
		{
			if (curType == "Long (8 Bytes)")
			{
				this->mValueToSearchFor.SetText(this->mValueIsHex ? FormatInt64HexUpper(ScanInt64(curInput)) : Format("%lli", ScanInt64(curInput, NULL, 16)));
				
			}
			else
			{
				this->mValueToSearchFor.SetText(this->mValueIsHex ? FormatHexadecimalIntSpecial(ScanInt(curInput)) : Format("%lli", ScanInt(curInput, NULL, 16)));
			}
		}
	}
	
	// Toggle a hexadecimal value representation for the second value field.
	if (!curSecondInput.IsEmpty())
	{
		if (curType != "String (Slower scan, be patient)" && curType != "Array of Bytes" && curType != "Float (4 Bytes)" && curType != "Double (8 Bytes)")
		{
			if (curType == "Long (8 Bytes)")
			{
				this->mSecondValueToSearchFor.SetText(this->mValueIsHex ? FormatInt64HexUpper(ScanInt64(curSecondInput)) : Format("%lli", ScanInt64(curSecondInput, NULL, 16)));
				
			}
			else
			{
				this->mSecondValueToSearchFor.SetText(this->mValueIsHex ? FormatHexadecimalIntSpecial(ScanInt(curSecondInput)) : Format("%lli", ScanInt(curSecondInput, NULL, 16)));
			}
		}
	}
}

// Executed when the user selects a scan type.
void CryNewScanForm::ScanTypeSelected()
{
	if (this->mScanTypeSelector.GetValue() == "Changed Value" || this->mScanTypeSelector.GetValue() == "Unchanged Value"
		|| this->mScanTypeSelector.GetValue() == "Increased Value" || this->mScanTypeSelector.GetValue() == "Decreased Value")
	{
		this->mValueInfoLabel.Disable();
		this->mValueIsHex.Disable();
		this->mValueToSearchFor.Disable();
		this->mValueSecondInfoLabel.Disable();
		this->mSecondValueToSearchFor.Disable();
	}
	else if (this->mScanTypeSelector.GetValue() == "Value Between")
	{
		this->mValueInfoLabel.Enable();
		this->mValueIsHex.Enable();
		this->mValueToSearchFor.Enable();
		this->mValueSecondInfoLabel.Enable();
		this->mSecondValueToSearchFor.Enable();
	}
	else if (this->mScanTypeSelector.GetValue() == "Unknown Initial Value")
	{
		this->mValueInfoLabel.Disable();
		this->mValueIsHex.Disable();
		this->mValueToSearchFor.Disable();
		this->mValueSecondInfoLabel.Disable();
		this->mSecondValueToSearchFor.Disable();
	}
	else
	{
		this->mValueInfoLabel.Enable();
		this->mValueIsHex.Enable();
		this->mValueToSearchFor.Enable();
		this->mValueSecondInfoLabel.Disable();
		this->mSecondValueToSearchFor.Disable();
	}
}

// Executed when the user selects a block size.
void CryNewScanForm::BlockSizeSelected()
{
	const String& selected = this->mBlockSizeSelector.GetValue();
	if (selected == "String (Slower scan, be patient)")
	{
		this->mValueToSearchFor.Enable();
		this->mValueSecondInfoLabel.Disable();
		this->mSecondValueToSearchFor.Disable();
		this->mValueIsHex.Disable();
		this->useFastScan.Disable();
		this->mScanTypeSelector.SetIndex(0);
		this->mScanTypeSelector.Disable();
		this->mScanTypeSelectorLabel.Disable();
		this->stringUnicode.Show();
		this->stringUntilNull.Show();
	}
	else if (selected == "Array of Bytes")
	{
		this->mValueToSearchFor.Enable();
		this->mValueSecondInfoLabel.Disable();
		this->mSecondValueToSearchFor.Disable();
		this->mValueIsHex.Disable();
		this->useFastScan.Disable();
		this->mScanTypeSelector.SetIndex(0);
		this->mScanTypeSelector.Disable();
		this->mScanTypeSelectorLabel.Disable();
		this->stringUnicode.Hide();
		this->stringUntilNull.Hide();
	}
	else if (selected == "Float (4 Bytes)" || selected == "Double (8 Bytes)")
	{
		this->mValueIsHex = false;
		this->mValueIsHex.Disable();
	}
	else
	{
		this->mValueIsHex.Enable(selected != "Float (4 Bytes)" && selected != "Double (8 Bytes)");
		this->useFastScan.Enable();
		this->mValueIsHex.Enable();
		this->mScanTypeSelector.Enable();
		this->mScanTypeSelectorLabel.Enable();
		this->stringUnicode.Hide();
		this->stringUntilNull.Hide();
		
		// Only enable the second value fields if the corresponding scan type was selected.
		if (this->mScanTypeSelector.GetValue() == "Value Between")
		{
			this->mValueSecondInfoLabel.Enable();
			this->mSecondValueToSearchFor.Enable();	
		}
	}
}

// Executed when the user clicks the OK button to accept the dialog.
void CryNewScanForm::OkButtonClicked()
{
	// Check whether the user inserted a proper value to search for.
	if (this->mValueToSearchFor.GetText().IsEmpty() && this->mScanTypeSelector.GetIndex() < 3)
	{
		Prompt("Input Error", CtrlImg::error(), "The inserted value is invalid!", "OK");
		return;
	}
	
	// In case the user desired a value in between, a second value also needs to be inserted.
	if (this->mSecondValueToSearchFor.GetText().IsEmpty() && this->mScanTypeSelector.GetValue() == "Value Between")
	{
		Prompt("Input Error", CtrlImg::error(), "Please insert a second value!", "OK");
		return;
	}
	
	// Check whether the array of bytes formatting was correct.
	if ((this->mBlockSizeSelector.GetIndex() == 6) && (this->mValueToSearchFor.GetLength() > 2 && this->mValueToSearchFor.GetText().Find(" ") == -1))
	{
		Prompt("Input Error", CtrlImg::error(), "Please format array of bytes correctly!&&Example: 0A FF B3", "OK");
		return;
	}
	
	// Delete the old scan parameter placeholder to create a new one.
	if (GlobalScanParameter)
	{
		delete GlobalScanParameter;
	}
	
	// Initialize the global scan parameter.
	switch (this->mBlockSizeSelector.GetIndex())
	{
		case 0: // byte
			GlobalScanParameter = new ScanParameters<Byte>();
			(reinterpret_cast<ScanParameters<Byte>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mValueToSearchFor.GetText().ToString());
			(reinterpret_cast<ScanParameters<Byte>*>(GlobalScanParameter))->OuterScanValue = this->mValueIsHex ? ScanInt(this->mSecondValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mSecondValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_BYTE;
			break;
		case 1: // 2 bytes
			GlobalScanParameter = new ScanParameters<short>();
			(reinterpret_cast<ScanParameters<short>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mValueToSearchFor.GetText().ToString());
			(reinterpret_cast<ScanParameters<short>*>(GlobalScanParameter))->OuterScanValue = this->mValueIsHex ? ScanInt(this->mSecondValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mSecondValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_2BYTES;
			break;
		case 2: // 4 bytes
			GlobalScanParameter = new ScanParameters<int>();
			(reinterpret_cast<ScanParameters<int>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mValueToSearchFor.GetText().ToString());
			(reinterpret_cast<ScanParameters<int>*>(GlobalScanParameter))->OuterScanValue = this->mValueIsHex ? ScanInt(this->mSecondValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mSecondValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_4BYTES;
			break;
		case 3: // 8 bytes
			GlobalScanParameter = new ScanParameters<__int64>();
			(reinterpret_cast<ScanParameters<__int64>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt64(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : atol(this->mValueToSearchFor.GetText().ToString());
			(reinterpret_cast<ScanParameters<__int64>*>(GlobalScanParameter))->OuterScanValue = this->mValueIsHex ? ScanInt64(this->mSecondValueToSearchFor.GetText().ToString(), NULL, 16) : atol(this->mSecondValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_8BYTES;
			break;
		case 4: // float
			GlobalScanParameter = new ScanParameters<float>();
			(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? (float)ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : (float)StrDbl(this->mValueToSearchFor.GetText().ToString());
			(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->OuterScanValue = this->mValueIsHex ? (float)ScanInt(this->mSecondValueToSearchFor.GetText().ToString(), NULL, 16) : (float)StrDbl(this->mSecondValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_FLOAT;
			break;
		case 5: // double
			GlobalScanParameter = new ScanParameters<double>();
			(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? (double)ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrDbl(this->mValueToSearchFor.GetText().ToString());
			(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->OuterScanValue = this->mValueIsHex ? (double)ScanInt(this->mSecondValueToSearchFor.GetText().ToString(), NULL, 16) : StrDbl(this->mSecondValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_DOUBLE;
			break;
		case 6: // aob
			GlobalScanParameter = new ScanParameters<ArrayOfBytes>();
			{
				ArrayOfBytes aob = StringToBytes(this->mValueToSearchFor.GetText().ToString());
				GlobalScanParameter->ValueSize = aob.Size;
				(reinterpret_cast<ScanParameters<ArrayOfBytes>*>(GlobalScanParameter))->ScanValue = aob;		
				GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_AOB;
			}
			break;
		case 7: // string
			if (this->stringUnicode)
			{
				// Unicode string
				GlobalScanParameter = new ScanParameters<WString>();
				(reinterpret_cast<ScanParameters<WString>*>(GlobalScanParameter))->ScanValue = this->mValueToSearchFor.GetText();
				GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_WSTRING;
				GlobalScanParameter->ValueSize = this->mValueToSearchFor.GetLength() * 2;
			}
			else
			{
				// C string
				GlobalScanParameter = new ScanParameters<String>();
				(reinterpret_cast<ScanParameters<String>*>(GlobalScanParameter))->ScanValue = this->mValueToSearchFor.GetText().ToString();
				GlobalScanParameter->GlobalScanValueType = CRYDATATYPE_STRING;
				GlobalScanParameter->ValueSize = this->mValueToSearchFor.GetLength();
			}
			GlobalScanParameter->ScanUntilNullChar = this->stringUntilNull;
			break;
	}
	
	// Set additional scanner parameters.
	GlobalScanParameter->CurrentScanFastScan = this->useFastScan;
	GlobalScanParameter->CurrentScanHexValues = this->mValueIsHex.IsEnabled() ? this->mValueIsHex : false;
	
	// String or WString types can only comply to exact match, all other types can also comply to other operators.
	if (GlobalScanParameter->GlobalScanValueType == CRYDATATYPE_STRING || GlobalScanParameter->GlobalScanValueType == CRYDATATYPE_WSTRING
		|| GlobalScanParameter->GlobalScanValueType == CRYDATATYPE_AOB)
	{
		GlobalScanParameter->GlobalScanType = SCANTYPE_EXACTVALUE;
	}
	else
	{
		GlobalScanParameter->GlobalScanType = GetMemoryScanTypeFromStringRepresentation(this->mScanTypeSelector.GetValue());
	}
	
	// Accept the dialog.
	this->AcceptBreak(10);
}