#include "CryChangeRecordDialog.h"
#include "ImlProvider.h"

#ifdef _WIN64
CryChangeRecordDialog::CryChangeRecordDialog(AddressTable& addrTable, const __int64 address, const String& type, ChangeRecordDialogMode mode) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
#else
CryChangeRecordDialog::CryChangeRecordDialog(AddressTable& addrTable, const int address, const String& type, ChangeRecordDialogMode mode) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
#endif
{
	this->mMode = mode;
	this->mLoadedTable = &addrTable;
	this->mLoadedEntry = (mode == CDRM_MANUALNEW) ? new AddressTableEntry() : const_cast<AddressTableEntry*>(addrTable[addrTable.Find(address, type)]);
	
	// Apply appropriate window title for used open mode.
	switch (mode)
	{
		case CDRM_MANUALNEW:
			this->Title("Change Address");
			break;
		case CRDM_DESCRIPTION:
			this->Title("Change Description");
			this->mFieldValue.SetText(this->mLoadedEntry->Description);
			break;
		case CRDM_ADDRESS:
			this->Title("Change Address");
#ifdef _WIN64
			this->mFieldValue.SetText(Format("%llX", this->mLoadedEntry->Address));
#else
			this->mFieldValue.SetText(Format("%lX", this->mLoadedEntry->Address));
#endif
			break;
		case CRDM_VALUE:
			this->Title("Change Value");
			this->mFieldValue.SetText(this->mLoadedEntry->Value);
			break;
		case CRDM_TYPE:
			this->Title("Change Type");
			break;
	}
	
	this->SetRect(0, 0, 250, 100);
	
	this->mCancel <<= THISBACK(CancelDialog);
	this->mOk <<= THISBACK(DialogOkay);
	
	this->mTypeSelector.WhenAction = THISBACK(BlockSizeSelected);
	
	*this
		<< this->mCancel.SetLabel("Cancel").HSizePos(190, 5).BottomPos(5, 25)
		<< this->mOk.Ok().SetLabel("OK").HSizePos(130, 60).BottomPos(5, 25)
	;
	
	// If the window is opened for altering the data type of an entry, add the necessary controls.
	if (mode == CRDM_TYPE)
	{
		*this
			<< this->mTypeSelector.Add("Byte").Add("2 Bytes").Add("4 Bytes").Add("8 Bytes").Add("Float").Add("Double")
				.Add("Array of Bytes").Add("String").HSizePos(92, 5).TopPos(5, 20)
			<< this->mUnicodeString.SetLabel("Unicode").HSizePos(5, 5).TopPos(30, 20)
		;
		
		if (this->mLoadedEntry->ValueType != "String" && this->mLoadedEntry->ValueType != "WString")
		{
			this->mUnicodeString.Hide();
		}
	}
	else
	{
		*this << this->mFieldValue.HSizePos(110, 5).TopPos(5, 20);
	}
	
	// Add appropriate controls for used open mode.
	switch (mode)
	{
		case CDRM_MANUALNEW:
			*this
				<< this->mFieldDescription.SetLabel("Address (Hex):").HSizePos(5, 100).TopPos(5, 20)
			;
			break;
		case CRDM_DESCRIPTION:
			*this
				<< this->mFieldDescription.SetLabel("Description:").HSizePos(5, 100).TopPos(5, 20)
			;
			break;
		case CRDM_ADDRESS:
			*this
				<< this->mFieldDescription.SetLabel("Address (Hex):").HSizePos(5, 100).TopPos(5, 20)
			;
			break;
		case CRDM_VALUE:
			*this
				<< this->mFieldDescription.SetLabel("Value:").HSizePos(5, 100).TopPos(5, 20)
			;
			
			if (this->mLoadedEntry->ValueType == "Byte" || this->mLoadedEntry->ValueType == "2 Bytes" ||
			    this->mLoadedEntry->ValueType == "4 Bytes" || this->mLoadedEntry->ValueType == "8 Bytes")
			{
				*this << this->mValueIsHex.SetLabel("Hexadecimal").HSizePos(5, 100).TopPos(30, 20);
				this->mValueIsHex.WhenAction = THISBACK(ValueModeHexOptionChanged);
			}
			break;
		case CRDM_TYPE:
			*this
				<< this->mFieldDescription.SetLabel("Type:").HSizePos(5, 100).TopPos(5, 20)
			;
			
			if (this->mLoadedEntry->ValueType == "Byte")
			{
				this->mTypeSelector.SetIndex(0);
			}
			else if (this->mLoadedEntry->ValueType == "2 Bytes")
			{
				this->mTypeSelector.SetIndex(1);
			}
			else if (this->mLoadedEntry->ValueType == "4 Bytes")
			{
				this->mTypeSelector.SetIndex(2);
			}
			else if (this->mLoadedEntry->ValueType == "8 Bytes")
			{
				this->mTypeSelector.SetIndex(3);
			}
			else if (this->mLoadedEntry->ValueType == "Float")
			{
				this->mTypeSelector.SetIndex(4);
			}
			else if (this->mLoadedEntry->ValueType == "Double")
			{
				this->mTypeSelector.SetIndex(5);
			}
			else if (this->mLoadedEntry->ValueType == "Array of Bytes")
			{
				this->mTypeSelector.SetIndex(6);
			}
			else if (this->mLoadedEntry->ValueType == "String")
			{
				this->mTypeSelector.SetIndex(7);
			}
			else if (this->mLoadedEntry->ValueType == "WString")
			{
				this->mTypeSelector.SetIndex(7);
				this->mUnicodeString = true;
			}
			break;
	}
}

CryChangeRecordDialog::~CryChangeRecordDialog()
{
	
}

void CryChangeRecordDialog::ValueModeHexOptionChanged()
{
	if (this->mValueIsHex)
	{
		if (this->mLoadedEntry->ValueType == "8 Bytes")
		{
			__int64 v = ScanInt64(this->mFieldValue.GetText().ToString());
			this->mFieldValue.SetText(Format("%llX", v));
		}
		else if (this->mLoadedEntry->ValueType == "4 Bytes")
		{
			int v = ScanInt(this->mFieldValue.GetText().ToString());
			this->mFieldValue.SetText(Format("%lX", v));
		}
		else if (this->mLoadedEntry->ValueType == "2 Bytes")
		{
			short v = ScanInt(this->mFieldValue.GetText().ToString());
			char text[64];
			sprintf_s(text, 64, "%hX", v);
			this->mFieldValue.SetText(text);	
		}
		else if (this->mLoadedEntry->ValueType == "Byte")
		{
			Byte v = ScanInt(this->mFieldValue.GetText().ToString());
			char text[64];
			sprintf_s(text, 64, "%hhX", v);
			this->mFieldValue.SetText(text);
		}
	}
	else
	{
		if (this->mLoadedEntry->ValueType == "8 Bytes")
		{
			__int64 v = ScanInt64(this->mFieldValue.GetText().ToString(), NULL, 16);
			this->mFieldValue.SetText(Format("%lli", v));
		}
		else if (this->mLoadedEntry->ValueType == "4 Bytes")
		{
			int v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			this->mFieldValue.SetText(Format("%li", v));
		}
		else if (this->mLoadedEntry->ValueType == "2 Bytes")
		{
			short v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			char text[64];
			sprintf_s(text, 64, "%hi", v);
			this->mFieldValue.SetText(text);
		}
		else if (this->mLoadedEntry->ValueType == "Byte")
		{
			Byte v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			char text[64];
			sprintf_s(text, 64, "%hhi", v);
			this->mFieldValue.SetText(text);
		}		
	}
}

void CryChangeRecordDialog::BlockSizeSelected()
{
	// If the data type 'String' is selected, the option to select Unicode should become visible.
	if (this->mTypeSelector.GetIndex() == 7)
	{
		this->mUnicodeString.Show();
	}
	else
	{
		this->mUnicodeString.Hide();
	}
}

void CryChangeRecordDialog::CancelDialog()
{
	if (this->mMode == CDRM_MANUALNEW)
	{
		delete this->mLoadedEntry;
	}
	
	this->Close();
}

void CryChangeRecordDialog::DialogOkay()
{
	// Apply appropriate change to addresstable instance.
	switch (this->mMode)
	{
		case CDRM_MANUALNEW:
			if (this->mFieldValue.GetText().IsEmpty())
			{
				Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
				return;
			}
#ifdef _WIN64
			this->mLoadedEntry->Address = ScanInt64(this->mFieldValue.GetText().ToString(), NULL, 16);
#else
			this->mLoadedEntry->Address = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
#endif	
			
			// Copy entry to table and delete local one.
			this->mLoadedTable->Add("", this->mLoadedEntry->Address, this->mLoadedEntry->ValueType);
			delete this->mLoadedEntry;
			break;
		case CRDM_DESCRIPTION:
			this->mLoadedEntry->Description = this->mFieldValue.GetText().ToString();
			break;
		case CRDM_ADDRESS:
			if (this->mFieldValue.GetText().IsEmpty())
			{
				Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
				return;
			}
#ifdef _WIN64
			this->mLoadedEntry->Address = ScanInt64(this->mFieldValue.GetText().ToString(), NULL, 16);
#else
			this->mLoadedEntry->Address = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
#endif
			break;
		case CRDM_VALUE:
			if (this->mFieldValue.GetText().IsEmpty())
			{
				Prompt("Input Error", CtrlImg::error(), "Please enter a value.", "OK");
				return;
			}
			
			// Value is not managed by address table itself, so WPM.
			if (this->mLoadedEntry->ValueType == "Byte")
			{
				if (this->mValueIsHex)
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, (Byte)ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16));
				}
				else
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, (Byte)ScanInt(this->mFieldValue.GetText().ToString()));
				}
			}
			else if (this->mLoadedEntry->ValueType == "2 Bytes")
			{
				if (this->mValueIsHex)
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, (short)ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16));
				}
				else
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, (short)ScanInt(this->mFieldValue.GetText().ToString()));
				}
			}
			else if (this->mLoadedEntry->ValueType == "4 Bytes")
			{
				if (this->mValueIsHex)
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16));
				}
				else
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt(this->mFieldValue.GetText().ToString()));
				}
			}
			else if (this->mLoadedEntry->ValueType == "8 Bytes")
			{
				if (this->mValueIsHex)
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt64(this->mFieldValue.GetText().ToString(), NULL, 16));
				}
				else
				{
					mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt64(this->mFieldValue.GetText().ToString()));
				}
			}
			else if (this->mLoadedEntry->ValueType == "Float")
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, (float)ScanDouble(this->mFieldValue.GetText().ToString(), NULL, true));
			}
			else if (this->mLoadedEntry->ValueType == "Double")
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanDouble(this->mFieldValue.GetText().ToString(), NULL, true));
			}
			else if (this->mLoadedEntry->ValueType == "String")
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, this->mFieldValue.GetText().ToString());
				this->mLoadedEntry->Size = this->mFieldValue.GetLength();
			}
			else if (this->mLoadedEntry->ValueType == "WString")
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, this->mFieldValue.GetText());
				this->mLoadedEntry->Size = this->mFieldValue.GetLength();
			}
			else if (this->mLoadedEntry->ValueType == "Array of Bytes")
			{
				ArrayOfBytes aob = StringToBytes(this->mFieldValue.GetText().ToString());	
				mMemoryScanner->Poke(this->mLoadedEntry->Address, aob);
				this->mLoadedEntry->Size = aob.Size;
			}
			break;
		case CRDM_TYPE:
			switch (this->mTypeSelector.GetIndex())
			{
				case 0:
					this->mLoadedEntry->ValueType = "Byte";
					break;
				case 1:
					this->mLoadedEntry->ValueType = "2 Bytes";
					break;
				case 2:
					this->mLoadedEntry->ValueType = "4 Bytes";
					break;
				case 3:
					this->mLoadedEntry->ValueType = "8 Bytes";
					break;
				case 4:
					this->mLoadedEntry->ValueType = "Float";
					break;
				case 5:
					this->mLoadedEntry->ValueType = "Double";
					break;
				case 6:
					this->mLoadedEntry->ValueType = "Array of Bytes";
					break;
				case 7:
					if (this->mUnicodeString)
					{
						this->mLoadedEntry->ValueType = "WString";
					}
					else
					{
						this->mLoadedEntry->ValueType = "String";
					}
					break;
				default:
					// The compiler cannot know what value GetIndex() will return so it must be made assume that the value will not exceed the cases.
					__assume(0);
			}
			break;
	}
	
	this->Close();
}