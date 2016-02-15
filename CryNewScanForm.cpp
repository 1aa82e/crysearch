#include "CryNewScanForm.h"
#include "UIUtilities.h"

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

CryNewScanForm::CryNewScanForm(bool FirstScan, const Image& icon) : CryDialogTemplate(icon)
{
	this->mNextScan = !FirstScan;
	
	this->Title(FirstScan ? "New Scan" : "Next Scan").SetRect(0, 0, 275, 130);
	
	this->mOk <<= THISBACK(OkButtonClicked);
	this->Rejector(this->mCancel, IDCANCEL);
	
	*this
		<< this->mValueInfoLabel.SetLabel("Value:").LeftPos(5, 75).TopPos(5, 20)
		<< this->mValueIsHex.SetLabel("Hex").LeftPos(75, 50).TopPos(5, 20)
		<< this->mValueToSearchFor.HSizePos(130, 5).TopPos(5, 20)
		<< this->mBlockSizeSelectorLabel.SetLabel("Size:").LeftPos(5, 75).TopPos(30, 20)
		<< this->mBlockSizeSelector.Add("Byte").Add("Short (2 Bytes)").Add("Integer (4 Bytes)")
			.Add("Long (8 Bytes)").Add("Float (4 Bytes)").Add("Double (8 Bytes)").Add("Array of Bytes")
			.Add("String (Slower scan, be patient)").HSizePos(75, 5).TopPos(30, 20)
		<< this->mScanTypeSelectorLabel.SetLabel("Type:").LeftPos(5, 75).TopPos(55, 20)
		<< this->mScanTypeSelector.Add("Exact Value").Add("Smaller Than").Add("Greater Than").HSizePos(75, 5).TopPos(55, 20)
		<< this->useFastScan.Set(SettingsFile::GetInstance()->GetFastScanByDefault()).SetLabel("Fast Scan")
			.LeftPos(5, 75).TopPos(75, 25)
		<< this->stringUnicode.SetLabel("Unicode").RightPos(5, 75).TopPos(75, 25)
		<< this->stringUntilNull.SetLabel("Match until null").HSizePos(80, 80).TopPos(75, 25)
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
	
	if (!FirstScan)
	{
		this->useFastScan = GlobalScanParameter->CurrentScanFastScan;
		
		switch(GlobalScanParameter->GlobalScanValueType)
		{
			case VALUETYPE_BYTE:
				this->mBlockSizeSelector.SetIndex(0);
				break;
			case VALUETYPE_2BYTE:
				this->mBlockSizeSelector.SetIndex(1);
				break;
			case VALUETYPE_4BYTE:
				this->mBlockSizeSelector.SetIndex(2);
				break;
			case VALUETYPE_8BYTE:
				this->mBlockSizeSelector.SetIndex(3);
				break;
			case VALUETYPE_FLOAT:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(4);
				break;
			case VALUETYPE_DOUBLE:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(5);
				break;
			case VALUETYPE_AOB:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(6);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				break;
			case VALUETYPE_STRING:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(7);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				break;
			case VALUETYPE_WSTRING:
				this->mValueIsHex.Disable();
				this->mBlockSizeSelector.SetIndex(7);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				this->stringUnicode.Show();
				this->stringUnicode = true;
				this->stringUnicode.Disable();
				break;
		}
		
		this->mScanTypeSelector.Add("Changed Value");
		this->mScanTypeSelector.Add("Unchanged Value");
		this->mScanTypeSelector.Add("Increased Value");
		this->mScanTypeSelector.Add("Decreased Value");
		
		if (GlobalScanParameter->GlobalScanType == SCANTYPE_CHANGED || GlobalScanParameter->GlobalScanType == SCANTYPE_UNCHANGED
			|| GlobalScanParameter->GlobalScanType == SCANTYPE_INCREASED || GlobalScanParameter->GlobalScanType == SCANTYPE_DECREASED)
		{
			this->mValueInfoLabel.Disable();
			this->mValueToSearchFor.Disable();
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
	}
}

CryNewScanForm::~CryNewScanForm()
{
	
}

void CryNewScanForm::ValueInputHexToggleChanged()
{
	const String& curInput = this->mValueToSearchFor.GetText().ToString();
	const String& curType = this->mBlockSizeSelector.GetValue();
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
}

void CryNewScanForm::ScanTypeSelected()
{
	if (this->mScanTypeSelector.GetValue() == "Changed Value" || this->mScanTypeSelector.GetValue() == "Unchanged Value"
		|| this->mScanTypeSelector.GetValue() == "Increased Value" || this->mScanTypeSelector.GetValue() == "Decreased Value")
	{
		this->mValueInfoLabel.Disable();
		this->mValueIsHex.Disable();
		this->mValueToSearchFor.Disable();
	}
	else if (this->mScanTypeSelector.GetValue() == "Unknown Initial Value")
	{
		this->mValueInfoLabel.Disable();
		this->mValueIsHex.Disable();
		this->mValueToSearchFor.Disable();
	}
	else
	{
		this->mValueInfoLabel.Enable();
		this->mValueIsHex.Enable();
		this->mValueToSearchFor.Enable();
	}
}

void CryNewScanForm::BlockSizeSelected()
{
	const String& selected = this->mBlockSizeSelector.GetValue();
	if (selected == "String (Slower scan, be patient)")
	{
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
		this->mValueIsHex.Disable();
		this->useFastScan.Disable();
		this->mScanTypeSelector.SetIndex(0);
		this->mScanTypeSelector.Disable();
		this->mScanTypeSelectorLabel.Disable();
		this->stringUnicode.Hide();
		this->stringUntilNull.Hide();
	}
	else
	{
		this->mValueIsHex.Enable(selected != "Float (4 Bytes)" && selected != "Double (8 Bytes)");		
		this->useFastScan.Enable();
		this->mScanTypeSelector.Enable();
		this->mScanTypeSelectorLabel.Enable();
		this->stringUnicode.Hide();
		this->stringUntilNull.Hide();
	}
}

void CryNewScanForm::OkButtonClicked()
{
	if (((String)this->mValueToSearchFor).IsEmpty() && this->mScanTypeSelector.GetIndex() < 3)
	{
		Prompt("Input Error", CtrlImg::error(), "The inserted value is invalid!", "OK");
		return;
	}
	
	if ((this->mBlockSizeSelector.GetIndex() == 6) && (this->mValueToSearchFor.GetLength() > 2 && ((String)this->mValueToSearchFor).Find(" ") == -1))
	{
		Prompt("Input Error", CtrlImg::error(), "Please format array of bytes correctly!&&Example: 0A FF B3", "OK");
		return;
	}
	
	// Delete the old scan parameter placeholder to create a new one.
	if (GlobalScanParameter)
	{
		delete GlobalScanParameter;
	}

	switch(this->mBlockSizeSelector.GetIndex())
	{
		case 0: // byte
			GlobalScanParameter = new ScanParameters<Byte>();
			(reinterpret_cast<ScanParameters<Byte>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_BYTE;
			break;
		case 1: // 2 bytes
			GlobalScanParameter = new ScanParameters<short>();
			(reinterpret_cast<ScanParameters<short>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_2BYTE;
			break;
		case 2: // 4 bytes
			GlobalScanParameter = new ScanParameters<int>();
			(reinterpret_cast<ScanParameters<int>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrInt(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_4BYTE;
			break;
		case 3: // 8 bytes
			GlobalScanParameter = new ScanParameters<__int64>();
			(reinterpret_cast<ScanParameters<__int64>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? ScanInt64(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : atol(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_8BYTE;
			break;
		case 4: // float
			GlobalScanParameter = new ScanParameters<float>();
			(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? (float)ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : (float)StrDbl(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_FLOAT;
			break;
		case 5: // double
			GlobalScanParameter = new ScanParameters<double>();
			(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->ScanValue = this->mValueIsHex ? (double)ScanInt(this->mValueToSearchFor.GetText().ToString(), NULL, 16) : StrDbl(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_DOUBLE;
			break;
		case 6: // aob
			GlobalScanParameter = new ScanParameters<ArrayOfBytes>();
			{
				ArrayOfBytes aob = StringToBytes(this->mValueToSearchFor.GetText().ToString());
				GlobalScanParameter->ValueSize = aob.Size;
				(reinterpret_cast<ScanParameters<ArrayOfBytes>*>(GlobalScanParameter))->ScanValue = aob;		
				GlobalScanParameter->GlobalScanValueType = VALUETYPE_AOB;
			}
			break;
		case 7: // string
			if (this->stringUnicode)
			{
				// Unicode string
				GlobalScanParameter = new ScanParameters<WString>();
				(reinterpret_cast<ScanParameters<WString>*>(GlobalScanParameter))->ScanValue = this->mValueToSearchFor.GetText();
				GlobalScanParameter->GlobalScanValueType = VALUETYPE_WSTRING;
				GlobalScanParameter->ValueSize = this->mValueToSearchFor.GetLength() * 2;
			}
			else
			{
				// C string
				GlobalScanParameter = new ScanParameters<String>();
				(reinterpret_cast<ScanParameters<String>*>(GlobalScanParameter))->ScanValue = this->mValueToSearchFor.GetText().ToString();
				GlobalScanParameter->GlobalScanValueType = VALUETYPE_STRING;
				GlobalScanParameter->ValueSize = this->mValueToSearchFor.GetLength();
			}
			GlobalScanParameter->ScanUntilNullChar = this->stringUntilNull;
			break;
	}
	
	// Set additional scanner parameters.
	GlobalScanParameter->CurrentScanFastScan = this->useFastScan;
	GlobalScanParameter->CurrentScanHexValues = this->mValueIsHex.IsEnabled() ? this->mValueIsHex : false;
	
	// String or WString types can only comply to exact match, all other types can also comply to other operators.
	if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_STRING || GlobalScanParameter->GlobalScanValueType == VALUETYPE_WSTRING
		|| GlobalScanParameter->GlobalScanValueType == VALUETYPE_AOB)
	{
		GlobalScanParameter->GlobalScanType = SCANTYPE_EXACTVALUE;
	}
	else
	{
		GlobalScanParameter->GlobalScanType = GetMemoryScanTypeFromStringRepresentation(this->mScanTypeSelector.GetValue());
	}
	
	this->AcceptBreak(10);
}