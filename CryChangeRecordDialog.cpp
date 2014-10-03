#include "CryChangeRecordDialog.h"
#include "ImlProvider.h"

CryChangeRecordDialog::CryChangeRecordDialog(AddressTable& addrTable, const int row, ChangeRecordDialogMode mode) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
{
	this->mMode = mode;
	this->mLoadedTable = &addrTable;
	this->mLoadedEntry = (mode == CRDM_MANUALNEW) ? NULL : const_cast<AddressTableEntry*>(addrTable[row]);

	this->SetRect(0, 0, 250, 120);
	
	this->mCancel <<= THISBACK(CancelDialog);
	this->mOk <<= THISBACK(DialogOkay);
	this->mTypeSelector.WhenAction = THISBACK(BlockSizeSelected);
	
	*this
		<< this->mCancel.SetLabel("Cancel").HSizePos(190, 5).BottomPos(5, 25)
		<< this->mOk.Ok().SetLabel("OK").HSizePos(130, 60).BottomPos(5, 25)
	;
	
	// Begin: window open type specific user interface alter operations.
	if (mode == CRDM_DESCRIPTION)
	{
		*this
			<< this->mFieldDescription.SetLabel("Description:").HSizePos(5, 100).TopPos(5, 20)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 20)
		;
		
		this->Title("Change Description");
		this->mFieldValue.SetText(this->mLoadedEntry->Description);		
	}
	else if (mode == CRDM_ADDRESS)
	{
		*this
			<< this->mFieldDescription.SetLabel("Address (Hex):").HSizePos(5, 100).TopPos(5, 20)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 20)
		;
		
		this->Title("Change Address");
		
		// If the address is relative the display should be relative too.
		String str;
		if (this->mLoadedEntry->IsRelative && this->mLoadedTable->GetRelativeDisplayString(this->mLoadedEntry, str))
		{
			this->mFieldValue.SetText(str);
		}
		else
		{
#ifdef _WIN64
		this->mFieldValue.SetText(Format("%llX", this->mLoadedEntry->Address));
#else
		this->mFieldValue.SetText(Format("%lX", this->mLoadedEntry->Address));
#endif
		}
	}
	else if (mode == CRDM_TYPE)
	{
		this->Title("Change Type");
		
		// If the window is opened for altering the data type of an entry, add the necessary controls.
		*this
			<< this->mFieldDescription.SetLabel("Type:").HSizePos(5, 100).TopPos(5, 20)
			<< this->mTypeSelector.Add("Byte").Add("2 Bytes").Add("4 Bytes").Add("8 Bytes").Add("Float").Add("Double")
				.Add("Array of Bytes").Add("String").HSizePos(92, 5).TopPos(5, 20)
			<< this->mUnicodeString.SetLabel("Unicode").HSizePos(180, 5).TopPos(30, 20)
			<< this->mTypeLengthDescription.SetLabel("Length:").HSizePos(5, 100).TopPos(30, 20)
			<< this->mTypeLength.Min(1).HSizePos(92, 80).TopPos(30, 20)
		;
		
		// Value size depends on the current value type.
		this->mTypeLength = max(this->mLoadedEntry->Size, 1);
		
		// If the current value type is a string or wide string, the unicode checkbox must be made visible.
		if (this->mLoadedEntry->ValueType != "String" && this->mLoadedEntry->ValueType != "WString")
		{
			this->mUnicodeString.Hide();
			
			if (this->mLoadedEntry->ValueType != "Array of Bytes")
			{
				this->mTypeLengthDescription.Hide();
				this->mTypeLength.Hide();
			}
		}
		
		// Set current value type index for opened entry correctly.
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
	}
	else if (mode == CRDM_MANUALNEW)
	{
		this->Title("Add Address");
		
		*this
			<< this->mFieldDescription.SetLabel("Address (Hex):").HSizePos(5, 100).TopPos(5, 20)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 20)
			<< this->mSecondFieldDescription.SetLabel("Type:").HSizePos(5, 100).TopPos(30, 20)
			<< this->mTypeSelector.Add("Byte").Add("2 Bytes").Add("4 Bytes").Add("8 Bytes").Add("Float").Add("Double")
				.Add("Array of Bytes").Add("String").HSizePos(110, 5).TopPos(30, 20)
			<< this->mUnicodeString.SetLabel("Unicode").HSizePos(180, 5).TopPos(55, 20)
			<< this->mTypeLengthDescription.SetLabel("Length:").HSizePos(5, 100).TopPos(55, 20)
			<< this->mTypeLength.Min(1).HSizePos(110, 80).TopPos(55, 20)
		;
		
		// Manually added addresses will always have 0 as initial length, so 1 needs to be set as minimum.
		this->mTypeLength = 1;
		
		this->mUnicodeString.Hide();
		this->mTypeLengthDescription.Hide();
		this->mTypeLength.Hide();
		
		// Set the default data type for a manually added address to 4 bytes.
		this->mTypeSelector.SetIndex(2);
	}
	else if (mode == CRDM_VALUE)
	{
		*this
			<< this->mFieldDescription.SetLabel("Value:").HSizePos(5, 100).TopPos(5, 20)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 20)
		;
		
		this->Title("Change Value");
		this->mFieldValue.SetText(this->mLoadedEntry->Value);
		
		if (this->mLoadedEntry->ValueType == "Byte" || this->mLoadedEntry->ValueType == "2 Bytes" ||
		    this->mLoadedEntry->ValueType == "4 Bytes" || this->mLoadedEntry->ValueType == "8 Bytes")
		{
			*this << this->mValueIsHex.SetLabel("Hexadecimal").HSizePos(5, 100).TopPos(30, 20);
			this->mValueIsHex.WhenAction = THISBACK(ValueModeHexOptionChanged);
		}
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
	if (this->mTypeSelector.GetIndex() == 6)
	{
		this->mUnicodeString.Hide();
		this->mTypeLengthDescription.Show();
		this->mTypeLength.Show();		
	}
	else if (this->mTypeSelector.GetIndex() == 7)
	{
		this->mUnicodeString.Show();
		this->mTypeLengthDescription.Show();
		this->mTypeLength.Show();
	}
	else
	{
		this->mUnicodeString.Hide();
		this->mTypeLengthDescription.Hide();
		this->mTypeLength.Hide();
	}
}

void CryChangeRecordDialog::CancelDialog()
{
	this->Close();
}

void CryChangeRecordDialog::DialogOkay()
{
	// Temporarely save the edited values locally to avoid race conditions.
	LONG_PTR tempAddress;
	String tempType;
	int optionalSize = this->mLoadedEntry ? this->mLoadedEntry->Size : 0;
	
	// Globally save input value for every type.
	const String& inputVal = this->mFieldValue.GetText().ToString();
	
	// Apply appropriate change to addresstable instance.
	if (this->mMode == CRDM_MANUALNEW)
	{
		bool relative = false;
		
		// Check for empty input value.
		if (inputVal.IsEmpty())
		{
			Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
			return;
		}
		
		// If the address input contains a plus, the input is a relative address.
		const int plusIndex = inputVal.Find("+");
		if (plusIndex != -1)
		{
			// Parse the relative address into the new address table entry.
			const Win32ModuleInformation* mod = mModuleManager->FindModule(inputVal.Left(plusIndex));
			if (!mod)
			{
				// If the module was not found in the loaded modules list, the relative address cannot be calculated.
				Prompt("Input Error", CtrlImg::error(), "The typed module was not found!", "OK");
				return;
			}
			
			// Still here, so calculate the address.
			tempAddress = mod->BaseAddress + ScanInt(inputVal.Mid(plusIndex + 1), NULL, 16);
			relative = true;
		}
		else
		{
		
			// Regularly parse the address. It is not a relative one.	
#ifdef _WIN64
			tempAddress = ScanInt64(inputVal, NULL, 16);
#else
			tempAddress = ScanInt(inputVal, NULL, 16);
#endif
		}

		// Set the data type of the address table entry.
		if (this->mTypeSelector.GetIndex() == 6)
		{
			optionalSize = this->mTypeLength;
			tempType = this->mTypeSelector.Get();
		}
		else if (this->mTypeSelector.GetIndex() == 7)
		{
			optionalSize = this->mTypeLength;
			tempType = this->mUnicodeString ? "WString" : "String";
		}
		else
		{
			tempType = this->mTypeSelector.Get();
		}

		// Make sure the address combined with the selected data type isn't already present in the address table.
		if (this->mLoadedTable->Find(tempAddress, tempType) != -1)
		{
			Prompt("Input Error", CtrlImg::error(), "The selected address is already added to the table.", "OK");
			return;
		}

		// Copy entry to table and delete local one.
		const AddressTableEntry* newEntry = this->mLoadedTable->Add("", tempAddress, relative, tempType);
		newEntry->Size = optionalSize;
	}
	else if (this->mMode == CRDM_VALUE)
	{
		// Check for empty input value.
		if (inputVal.IsEmpty())
		{
			Prompt("Input Error", CtrlImg::error(), "Please enter a value.", "OK");
			return;
		}
		
		// Value is not managed by address table itself, so WPM.
		if (this->mLoadedEntry->ValueType == "Byte")
		{
			if (this->mValueIsHex)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, (Byte)ScanInt(inputVal, NULL, 16));
			}
			else
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, (Byte)ScanInt(inputVal));
			}
		}
		else if (this->mLoadedEntry->ValueType == "2 Bytes")
		{
			if (this->mValueIsHex)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, (short)ScanInt(inputVal, NULL, 16));
			}
			else
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, (short)ScanInt(inputVal));
			}
		}
		else if (this->mLoadedEntry->ValueType == "4 Bytes")
		{
			if (this->mValueIsHex)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt(inputVal, NULL, 16));
			}
			else
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt(inputVal));
			}
		}
		else if (this->mLoadedEntry->ValueType == "8 Bytes")
		{
			if (this->mValueIsHex)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt64(inputVal, NULL, 16));
			}
			else
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanInt64(inputVal));
			}
		}
		else if (this->mLoadedEntry->ValueType == "Float")
		{
			mMemoryScanner->Poke(this->mLoadedEntry->Address, (float)ScanDouble(inputVal, NULL, true));
		}
		else if (this->mLoadedEntry->ValueType == "Double")
		{
			mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanDouble(inputVal, NULL, true));
		}
		else if (this->mLoadedEntry->ValueType == "String")
		{
			mMemoryScanner->Poke(this->mLoadedEntry->Address, inputVal);
			this->mLoadedEntry->Size = this->mFieldValue.GetLength();
		}
		else if (this->mLoadedEntry->ValueType == "WString")
		{
			mMemoryScanner->Poke(this->mLoadedEntry->Address, this->mFieldValue.GetText());
			this->mLoadedEntry->Size = this->mFieldValue.GetLength();
		}
		else if (this->mLoadedEntry->ValueType == "Array of Bytes")
		{
			ArrayOfBytes aob = StringToBytes(inputVal);	
			mMemoryScanner->Poke(this->mLoadedEntry->Address, aob);
			this->mLoadedEntry->Size = aob.Size;
		}
	}
	else if (this->mMode == CRDM_TYPE)
	{
		// Assign proper value type including size parameter.
		if (this->mTypeSelector.GetIndex() == 6)
		{
			tempType = this->mTypeSelector.Get();
			optionalSize = this->mTypeLength;
		}
		else if (this->mTypeSelector.GetIndex() == 7)
		{
			tempType = this->mUnicodeString ? "WString" : "String";
			optionalSize = this->mTypeLength;
		}
		else
		{
			optionalSize = -1;
			tempType = this->mTypeSelector.Get();
		}

		// Make sure the address combined with the selected data type isn't already present in the address table.
		const int oldIndex = this->mLoadedTable->Find(this->mLoadedEntry->Address, tempType);
		if ((oldIndex != -1) && ((*this->mLoadedTable)[oldIndex] != this->mLoadedEntry))
		{
			Prompt("Input Error", CtrlImg::error(), "The selected address is already added to the table.", "OK");
			return;
		}
		
		// Finally, pass temporary values through to address table entry.
		this->mLoadedEntry->ValueType = tempType;
		this->mLoadedEntry->Size = optionalSize != -1 ? optionalSize : 0;
	}
	else if (this->mMode == CRDM_DESCRIPTION)
	{
		this->mLoadedEntry->Description = this->mFieldValue.GetText().ToString();
	}
	else if (this->mMode == CRDM_ADDRESS)
	{
		const String& inputVal = this->mFieldValue.GetText().ToString();
		// Check for empty input value.
		if (inputVal.IsEmpty())
		{
			Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
			return;
		}
		
		// Make sure the address combined with the selected data type isn't already present in the address table.
		const int oldIndex = this->mLoadedTable->Find(this->mLoadedEntry->Address, this->mLoadedEntry->ValueType);
		if ((oldIndex != -1) && ((*this->mLoadedTable)[oldIndex] != this->mLoadedEntry))
		{
			Prompt("Input Error", CtrlImg::error(), "The selected address is already added to the table.", "OK");
			return;
		}
		
		// If the address input contains a plus, the input is a relative address.
		const int plusIndex = inputVal.Find("+");
		if (plusIndex != -1)
		{
			// Parse the relative address into the existing address table entry.
			const Win32ModuleInformation* mod = mModuleManager->FindModule(inputVal.Left(plusIndex));
			if (!mod)
			{
				// If the module was not found in the loaded modules list, the relative address cannot be calculated.
				Prompt("Input Error", CtrlImg::error(), "The typed module was not found!", "OK");
				return;
			}
			
			// Still here, so calculate the address.
			this->mLoadedEntry->Address = mod->BaseAddress + ScanInt(inputVal.Mid(plusIndex + 1), NULL, 16);
			this->mLoadedEntry->IsRelative = true;
		}
		else
		{
		
			// Regularly parse the address. It is not a relative one.	
#ifdef _WIN64
			this->mLoadedEntry->Address = ScanInt64(inputVal, NULL, 16);
#else
			this->mLoadedEntry->Address = ScanInt(inputVal, NULL, 16);
#endif
			
			// Drop the relative flag from the address table entry.
			this->mLoadedEntry->IsRelative = false;
		}
	}
	
	// Close the form to pass execution back to the main window.
	this->Close();
}