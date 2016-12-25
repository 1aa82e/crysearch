#include "CryChangeRecordDialog.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"

// Default constructor for CryChangeRecordDialog.
CryChangeRecordDialog::CryChangeRecordDialog(AddressTable& addrTable, const Vector<int>& rows, ChangeRecordDialogMode mode) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
{
	this->mMode = mode;
	this->mLoadedTable = &addrTable;
	this->mLoadedEntry = (mode == CRDM_MANUALNEW) ? NULL : const_cast<AddressTableEntry*>(addrTable[rows[0]]);
	this->mRowArray = &rows;
	
	this->SetRect(0, 0, 250, 130);
	
	this->mCancel <<= THISBACK(CancelDialog);
	this->mOk <<= THISBACK(DialogOkay);
	this->mTypeSelector.WhenAction = THISBACK(BlockSizeSelected);
	
	*this
		<< this->mCancel.SetLabel("Cancel").RightPos(7, 70).BottomPos(5, 25)
		<< this->mOk.Ok().SetLabel("OK").RightPos(80, 70).BottomPos(5, 25)
	;
	
	// Begin: window open type specific user interface alter operations.
	if (mode == CRDM_DESCRIPTION)
	{
		*this
			<< this->mFieldDescription.SetLabel("Description:").HSizePos(5, 100).TopPos(5, 25)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 25)
		;
		
		this->Title("Change Description");
		this->mFieldValue.SetText(this->mLoadedEntry->Description);
	}
	else if (mode == CRDM_ADDRESS)
	{
		*this
			<< this->mFieldDescription.SetLabel("Address (Hex):").HSizePos(5, 100).TopPos(5, 25)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 25)
		;
		
		this->Title("Change Address");
		
		// If the address is relative the display should be relative too.
		String str;
		if (this->mLoadedEntry->IsRelative == TRUE && this->mLoadedTable->GetRelativeDisplayString(this->mLoadedEntry, str))
		{
			this->mFieldValue.SetText(str);
		}
		else
		{
#ifdef _WIN64
		this->mFieldValue.SetText(FormatInt64HexUpper(this->mLoadedEntry->Address));
#else
		this->mFieldValue.SetText(FormatHexadecimalIntSpecial(this->mLoadedEntry->Address));
#endif
		}
	}
	else if (mode == CRDM_TYPE)
	{
		this->Title("Change Type");
		
		// If the window is opened for altering the data type of an entry, add the necessary controls.
		*this
			<< this->mFieldDescription.SetLabel("Type:").HSizePos(5, 100).TopPos(5, 25)
			<< this->mTypeSelector.Add("Byte").Add("2 Bytes").Add("4 Bytes").Add("8 Bytes").Add("Float").Add("Double")
				.Add("Array of Bytes").Add("String").HSizePos(92, 5).TopPos(5, 25)
			<< this->mUnicodeString.SetLabel("Unicode").HSizePos(180, 5).TopPos(35, 25)
			<< this->mTypeLengthDescription.SetLabel("Length:").HSizePos(5, 100).TopPos(35, 25)
			<< this->mTypeLength.Min(1).HSizePos(92, 80).TopPos(35, 25)
		;
		
		// Value size depends on the current value type.
		this->mTypeLength = max(this->mLoadedEntry->Size, 1);
		
		// If the current value type is a string or wide string, the unicode checkbox must be made visible.
		if (this->mLoadedEntry->ValueType != CRYDATATYPE_STRING && this->mLoadedEntry->ValueType != CRYDATATYPE_WSTRING)
		{
			this->mUnicodeString.Hide();
			
			if (this->mLoadedEntry->ValueType != CRYDATATYPE_AOB)
			{
				this->mTypeLengthDescription.Hide();
				this->mTypeLength.Hide();
			}
		}
		
		// If the data type is a unicode string, enable the checkbox.
		if (this->mLoadedEntry->ValueType == CRYDATATYPE_WSTRING)
		{
			// Set current value type index for opened entry correctly.
			this->mTypeSelector.SetIndex(this->mLoadedEntry->ValueType - 1);
			this->mUnicodeString = true;
		}
		else
		{
			this->mTypeSelector.SetIndex(this->mLoadedEntry->ValueType);
		}
	}
	else if (mode == CRDM_MANUALNEW)
	{
		this->Title("Add Address");
		
		*this
			<< this->mFieldDescription.SetLabel("Address (Hex):").HSizePos(5, 100).TopPos(5, 25)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 25)
			<< this->mSecondFieldDescription.SetLabel("Type:").HSizePos(5, 100).TopPos(35, 25)
			<< this->mTypeSelector.Add("Byte").Add("2 Bytes").Add("4 Bytes").Add("8 Bytes").Add("Float").Add("Double")
				.Add("Array of Bytes").Add("String").HSizePos(110, 5).TopPos(35, 25)
			<< this->mUnicodeString.SetLabel("Unicode").HSizePos(180, 5).TopPos(60, 25)
			<< this->mTypeLengthDescription.SetLabel("Length:").HSizePos(5, 100).TopPos(60, 25)
			<< this->mTypeLength.Min(1).HSizePos(110, 80).TopPos(60, 25)
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
			<< this->mFieldDescription.SetLabel("Value:").HSizePos(5, 100).TopPos(5, 25)
			<< this->mFieldValue.HSizePos(110, 5).TopPos(5, 25)
		;
		
		this->Title("Change Value");
		this->mFieldValue.SetText(this->mLoadedEntry->Value);
		
		if (this->mLoadedEntry->ValueType == CRYDATATYPE_BYTE || this->mLoadedEntry->ValueType == CRYDATATYPE_2BYTES ||
		    this->mLoadedEntry->ValueType == CRYDATATYPE_4BYTES || this->mLoadedEntry->ValueType == CRYDATATYPE_8BYTES)
		{
			*this << this->mValueIsHex.SetLabel("Hexadecimal").HSizePos(5, 100).TopPos(35, 25);
			this->mValueIsHex.WhenAction = THISBACK(ValueModeHexOptionChanged);
		}
	}
}

// Default destructor for CryChangeRecordDialog.
CryChangeRecordDialog::~CryChangeRecordDialog()
{
	
}

// Executed when the user changes the view mode from decimal to hexadecimal and the other way around.
void CryChangeRecordDialog::ValueModeHexOptionChanged()
{
	if (this->mValueIsHex)
	{
		if (this->mLoadedEntry->ValueType == CRYDATATYPE_8BYTES)
		{
			__int64 v = ScanInt64(this->mFieldValue.GetText().ToString());
			this->mFieldValue.SetText(FormatInt64HexUpper(v));
		}
		else if (this->mLoadedEntry->ValueType == CRYDATATYPE_4BYTES)
		{
			int v = ScanInt(this->mFieldValue.GetText().ToString());
			this->mFieldValue.SetText(FormatHexadecimalIntSpecial(v));
		}
		else if (this->mLoadedEntry->ValueType == CRYDATATYPE_2BYTES)
		{
			short v = ScanInt(this->mFieldValue.GetText().ToString());
			char text[64];
			sprintf_s(text, 64, "%hX", v);
			this->mFieldValue.SetText(text);
		}
		else if (this->mLoadedEntry->ValueType == CRYDATATYPE_BYTE)
		{
			Byte v = ScanInt(this->mFieldValue.GetText().ToString());
			char text[64];
			sprintf_s(text, 64, "%hhX", v);
			this->mFieldValue.SetText(text);
		}
	}
	else
	{
		if (this->mLoadedEntry->ValueType == CRYDATATYPE_8BYTES)
		{
			__int64 v = ScanInt64(this->mFieldValue.GetText().ToString(), NULL, 16);
			this->mFieldValue.SetText(Format("%lli", v));
		}
		else if (this->mLoadedEntry->ValueType == CRYDATATYPE_4BYTES)
		{
			int v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			this->mFieldValue.SetText(Format("%li", v));
		}
		else if (this->mLoadedEntry->ValueType == CRYDATATYPE_2BYTES)
		{
			short v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			char text[64];
			sprintf_s(text, 64, "%hi", v);
			this->mFieldValue.SetText(text);
		}
		else if (this->mLoadedEntry->ValueType == CRYDATATYPE_BYTE)
		{
			Byte v = ScanInt(this->mFieldValue.GetText().ToString(), NULL, 16);
			char text[64];
			sprintf_s(text, 64, "%hhu", v);
			this->mFieldValue.SetText(text);
		}
	}
}

// Executed when the user changes the blocksize (data type size) of the entry.
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

// Executed when the user cancels dialog input.
void CryChangeRecordDialog::CancelDialog()
{
	this->Close();
}

// In case of a string or wstring, alter the size of the associated search result.
void CryChangeRecordDialog::AlterSearchResult(const SIZE_T address, const int size)
{
	const int count = CachedAddresses.GetCount();
	for (int i = 0; i < count; ++i)
	{
		if (CachedAddresses[i].Address == address)
		{
			CachedAddresses[i].StringLength = size;
			break;
		}
	}
}

// Executed when the user accepts the dialog input.
void CryChangeRecordDialog::DialogOkay()
{
	// Temporarely save the edited values locally to avoid race conditions.
	CCryDataType tempType;
	int optionalSize = this->mLoadedEntry ? this->mLoadedEntry->Size : 0;
	
	// Globally save input value for every type.
	const String& inputVal = this->mFieldValue.GetText().ToString();
	
	// A new entry should be manually added.
	if (this->mMode == CRDM_MANUALNEW)
	{
		LONG_PTR tempAddress;
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
		const int newindex = this->mTypeSelector.GetIndex();
		if (newindex == 6)
		{
			optionalSize = this->mTypeLength;
			tempType = newindex;
		}
		else if (this->mTypeSelector.GetIndex() == 7)
		{
			optionalSize = this->mTypeLength;
			tempType = this->mUnicodeString ? CRYDATATYPE_WSTRING : CRYDATATYPE_STRING;
		}
		else
		{
			tempType = newindex;
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

	// Make changes to every selected entry.
	for (int r : *this->mRowArray)
	{
		// Retrieve a pointer to the entry that must be edited next.
		this->mLoadedEntry = (*this->mLoadedTable)[r];
		
		// Edit the value of the selected entry.
		if (this->mMode == CRDM_VALUE)
		{
			// Check for empty input value.
			if (inputVal.IsEmpty())
			{
				Prompt("Input Error", CtrlImg::error(), "Please enter a value.", "OK");
				return;
			}
			
			// Value is not managed by address table itself, so WPM.
			if (this->mLoadedEntry->ValueType == CRYDATATYPE_BYTE)
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
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_2BYTES)
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
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_4BYTES)
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
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_8BYTES)
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
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_FLOAT)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, (float)ScanDouble(inputVal, NULL, true));
			}
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_DOUBLE)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, ScanDouble(inputVal, NULL, true));
			}
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_STRING)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, inputVal);
				this->mLoadedEntry->Size = this->mFieldValue.GetLength();
				this->AlterSearchResult(this->mLoadedEntry->Address, this->mLoadedEntry->Size);
			}
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_WSTRING)
			{
				mMemoryScanner->Poke(this->mLoadedEntry->Address, this->mFieldValue.GetText());
				this->mLoadedEntry->Size = this->mFieldValue.GetLength();
				this->AlterSearchResult(this->mLoadedEntry->Address, this->mLoadedEntry->Size);
			}
			else if (this->mLoadedEntry->ValueType == CRYDATATYPE_AOB)
			{
				ArrayOfBytes aob = StringToBytes(inputVal);
				mMemoryScanner->Poke(this->mLoadedEntry->Address, aob);
				this->mLoadedEntry->Size = aob.Size;
				this->AlterSearchResult(this->mLoadedEntry->Address, this->mLoadedEntry->Size);
			}
		}
		// Edit the type of the selected entry.
		else if (this->mMode == CRDM_TYPE)
		{
			// Assign proper value type including size parameter.
			const int newindex = this->mTypeSelector.GetIndex();
			if (newindex == 6)
			{
				tempType = newindex;
				optionalSize = this->mTypeLength;
			}
			else if (this->mTypeSelector.GetIndex() == 7)
			{
				tempType = this->mUnicodeString ? CRYDATATYPE_WSTRING : CRYDATATYPE_STRING;
				optionalSize = this->mTypeLength;
			}
			else
			{
				optionalSize = -1;
				tempType = newindex;
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
		// Edit the description of the selected entry.
		else if (this->mMode == CRDM_DESCRIPTION)
		{
			this->mLoadedEntry->Description = this->mFieldValue.GetText().ToString();
		}
		// Edit the address of the selected entry. This mode is only available if just one entry is selected.
		else if (this->mMode == CRDM_ADDRESS)
		{
			// Check for empty input value.
			if (inputVal.IsEmpty())
			{
				Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
				return;
			}
	
			LONG_PTR tempAddress;
			bool relative = false;
			
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
			
			// Make sure the address combined with the selected data type isn't already present in the address table.
			const int oldIndex = this->mLoadedTable->Find(tempAddress, this->mLoadedEntry->ValueType);
			if ((oldIndex != -1) && ((*this->mLoadedTable)[oldIndex] != this->mLoadedEntry))
			{
				Prompt("Input Error", CtrlImg::error(), "The selected address is already added to the table.", "OK");
				return;
			}
			
			this->mLoadedEntry->Address = tempAddress;
			this->mLoadedEntry->IsRelative = relative;
			
			// If the module changed, it should be changed in the address table entry as well.
			if (relative)
			{
				this->mLoadedEntry->ModuleName = mModuleManager->GetModuleFilename(tempAddress);
			}
		}
	}
	
	// Close the form to pass execution back to the main window.
	this->Close();
}