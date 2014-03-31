#include "CryNewScanForm.h"
#include "UIUtilities.h"

// Disable warning for conversion from double to float.
#pragma warning(disable : 4244)

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

CryNewScanForm::CryNewScanForm(bool FirstScan)
{
	this->mNextScan = FirstScan;
	
	this->Title(FirstScan ? "New Scan" : "Next Scan").SetRect(0, 0, 275, 130);
	
	this->mOk <<= THISBACK(OkButtonClicked);
	this->Rejector(mCancel, IDCANCEL);
	
	*this
		<< this->mValueInfoLabel.SetLabel("Value:").LeftPos(5, 75).TopPos(5, 20)
		<< this->mValueToSearchFor.HSizePos(75, 5).TopPos(5, 20)
		<< this->mOk.Ok().SetLabel("OK").RightPos(85, 75).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(5, 75).BottomPos(5, 25)
		<< this->mBlockSizeSelectorLabel.SetLabel("Size:").LeftPos(5, 75).TopPos(30, 20)
		<< this->mBlockSizeSelector.Add("Byte").Add("Short (2 Bytes)").Add("Integer (4 Bytes)")
			.Add("Long (8 Bytes)").Add("Float (4 Bytes)").Add("Double (8 Bytes)").Add("Array of Bytes")
			.Add("String (Slower scan, be patient)").HSizePos(75, 5).TopPos(30, 20)
		<< this->mScanTypeSelectorLabel.SetLabel("Type:").LeftPos(5, 75).TopPos(55, 20)
		<< this->mScanTypeSelector.Add("Exact Value").Add("Smaller Than").Add("Greater Than").HSizePos(75, 5).TopPos(55, 20)
		<< this->useFastScan.Set(GlobalSettingsInstance.GetFastScanByDefault()).SetLabel("Fast Scan")
			.LeftPos(5, 100).TopPos(75, 25)
		<< this->stringUnicode.SetLabel("Unicode").RightPos(5, 75).TopPos(75, 25)
	;
	
	this->mBlockSizeSelector.WhenAction = THISBACK(BlockSizeSelected);
	this->mScanTypeSelector.WhenAction = THISBACK(ScanTypeSelected);
	
	this->mBlockSizeSelectorLabel.Enable(FirstScan);
	this->mBlockSizeSelector.Enable(FirstScan);
	this->useFastScan.Enable(FirstScan);
	this->stringUnicode.Hide();
	
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
				this->mBlockSizeSelector.SetIndex(4);
				break;
			case VALUETYPE_DOUBLE:
				this->mBlockSizeSelector.SetIndex(5);
				break;
			case VALUETYPE_AOB:
				this->mBlockSizeSelector.SetIndex(6);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				break;
			case VALUETYPE_STRING:
				this->mBlockSizeSelector.SetIndex(7);
				this->mScanTypeSelector.Disable();
				this->mScanTypeSelectorLabel.Disable();
				break;
			case VALUETYPE_WSTRING:
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

bool CryNewScanForm::Key(dword key, int count)
{
	if (key == K_ESCAPE)
	{
		this->Close();
		return true;
	}
	
	return false;
}

CryNewScanForm::~CryNewScanForm()
{
	
}

void CryNewScanForm::ScanTypeSelected()
{
	if (this->mScanTypeSelector.GetValue() == "Changed Value" || this->mScanTypeSelector.GetValue() == "Unchanged Value"
		|| this->mScanTypeSelector.GetValue() == "Increased Value" || this->mScanTypeSelector.GetValue() == "Decreased Value")
	{
		this->mValueInfoLabel.Disable();
		this->mValueToSearchFor.Disable();
		
		if (this->mNextScan)
		{
			this->mBlockSizeSelectorLabel.Disable();
			this->mBlockSizeSelector.Disable();
		}
	}
	else if (this->mScanTypeSelector.GetValue() == "Unknown Initial Value")
	{
		this->mValueInfoLabel.Disable();
		this->mValueToSearchFor.Disable();
	}
	else
	{
		this->mValueInfoLabel.Enable();
		this->mValueToSearchFor.Enable();
		
		if (this->mNextScan)
		{
			this->mBlockSizeSelectorLabel.Enable();
			this->mBlockSizeSelector.Enable();
		}
	}
}

void CryNewScanForm::BlockSizeSelected()
{
	if (this->mBlockSizeSelector.GetValue() == "String (Slower scan, be patient)")
	{
		this->useFastScan.Disable();
		this->mScanTypeSelector.SetIndex(0);
		this->mScanTypeSelector.Disable();
		this->mScanTypeSelectorLabel.Disable();
		this->stringUnicode.Show();
	}
	else if (this->mBlockSizeSelector.GetValue() == "Array of Bytes")
	{
		this->useFastScan.Disable();
		this->mScanTypeSelector.SetIndex(0);
		this->mScanTypeSelector.Disable();
		this->mScanTypeSelectorLabel.Disable();
		this->stringUnicode.Hide();
	}
	else
	{
		this->useFastScan.Enable();
		this->mScanTypeSelector.Enable();
		this->mScanTypeSelectorLabel.Enable();
		this->stringUnicode.Hide();
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
	
	if (GlobalScanParameter)
	{
		delete GlobalScanParameter;
	}

	switch(this->mBlockSizeSelector.GetIndex())
	{
		case 0: // byte
			GlobalScanParameter = new ScanParameters<Byte>();
			((ScanParameters<Byte>*)GlobalScanParameter)->ScanValue = StrInt(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_BYTE;
			break;
		case 1: // 2 bytes
			GlobalScanParameter = new ScanParameters<short>();
			((ScanParameters<short>*)GlobalScanParameter)->ScanValue = StrInt(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_2BYTE;
			break;
		case 2: // 4 bytes
			GlobalScanParameter = new ScanParameters<int>();
			((ScanParameters<int>*)GlobalScanParameter)->ScanValue = StrInt(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_4BYTE;
			break;
		case 3: // 8 bytes
			GlobalScanParameter = new ScanParameters<__int64>();
			((ScanParameters<__int64>*)GlobalScanParameter)->ScanValue = atol(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_8BYTE;
			break;
		case 4: // float
			GlobalScanParameter = new ScanParameters<float>();
			((ScanParameters<float>*)GlobalScanParameter)->ScanValue = StrDbl(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_FLOAT;
			break;
		case 5: // double
			GlobalScanParameter = new ScanParameters<double>();
			((ScanParameters<double>*)GlobalScanParameter)->ScanValue = StrDbl(this->mValueToSearchFor.GetText().ToString());
			GlobalScanParameter->GlobalScanValueType = VALUETYPE_DOUBLE;
			break;
		case 6: // aob
			GlobalScanParameter = new ScanParameters<ArrayOfBytes>();
			
			{
				ArrayOfBytes aob = StringToBytes(this->mValueToSearchFor.GetText().ToString());
				
				if (!this->mNextScan)
				{
					GlobalScanParameter->ValueSize = aob.Size;
				}
				
				((ScanParameters<ArrayOfBytes>*)GlobalScanParameter)->ScanValue = aob;		
				GlobalScanParameter->GlobalScanValueType = VALUETYPE_AOB;
			}
			break;
		case 7: // string
			if (this->stringUnicode)
			{
				// Unicode string
				GlobalScanParameter = new ScanParameters<WString>();
				((ScanParameters<WString>*)GlobalScanParameter)->ScanValue = this->mValueToSearchFor.GetText();
				GlobalScanParameter->GlobalScanValueType = VALUETYPE_WSTRING;
				
				if (!this->mNextScan)				
				{
					GlobalScanParameter->ValueSize = this->mValueToSearchFor.GetLength() * 2;
				}
			}
			else
			{
				// C string
				GlobalScanParameter = new ScanParameters<String>();
				((ScanParameters<String>*)GlobalScanParameter)->ScanValue = this->mValueToSearchFor.GetText().ToString();
				GlobalScanParameter->GlobalScanValueType = VALUETYPE_STRING;
				
				if (!this->mNextScan)
				{
					GlobalScanParameter->ValueSize = this->mValueToSearchFor.GetLength();
				}
			}
			break;
	}
	
	// Indicate to the memory scanner that the current scan should be fast aligned scan.
	GlobalScanParameter->CurrentScanFastScan = this->useFastScan;
	
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