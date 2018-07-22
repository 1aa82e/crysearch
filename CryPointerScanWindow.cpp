#include "CryPointerScanWindow.h"
#include "ImlProvider.h"
#include "CryPointerScanSettings.h"
#include "BackendGlobalDef.h"

// Retrieves the string representation of the base address in a pointer scan result.
String GetPointerScanBaseAddress(const int index)
{
	return "";
}

// Retrieves the string representation of the offsets in a pointer scan result.
String GetPointerScanOffsets(const int index)
{
	return "";
}

// Retrieves the string representation of the value in a pointer scan result.
String GetPointerScanValue(const int index)
{
	return "";
}

// ---------------------------------------------------------------------------------------------

// CryPointerScanWindow default constructor.
CryPointerScanWindow::CryPointerScanWindow(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Pointer Scan").Zoomable().Sizeable().Icon(icon).SetRect(0, 0, 500, 400);
	
	this->AddFrame(this->mMenuBar);
	this->mMenuBar.Set(THISBACK(WindowMenuBar));
	
	*this << this->mPointerScanResults.NoMovingHeader().SizePos();
	
	this->mPointerScanResults.WhenBar = THISBACK(PointerScanRightClick);
	this->mPointerScanResults.CryAddRowNumColumn("Base Address", 40).SetConvert(Single<IndexBasedValueConvert<GetPointerScanBaseAddress>>());
	this->mPointerScanResults.CryAddRowNumColumn("Offsets", 30).SetConvert(Single<IndexBasedValueConvert<GetPointerScanOffsets>>());
	this->mPointerScanResults.CryAddRowNumColumn("Value", 30).SetConvert(Single<IndexBasedValueConvert<GetPointerScanValue>>());
}

// CryPointerScanWindow default destructor.
CryPointerScanWindow::~CryPointerScanWindow()
{
	
}

// Populates the main menu.
void CryPointerScanWindow::WindowMenuBar(Bar& pBar)
{
	pBar.Add("File", THISBACK(FileMenuBar));
}

// Populates the file menu.
void CryPointerScanWindow::FileMenuBar(Bar& pBar)
{
	pBar.Add("Pointer Scan", CrySearchIml::PointerScanSmall(), THISBACK(NewPointerScanClicked));
	pBar.Add("Close", CrySearchIml::ExitApplication(), THISBACK(CloseWindow));
}

// Closes the pointer scan window.
void CryPointerScanWindow::CloseWindow()
{
	this->Close();
}

// Populates the arrayctrl context menu.
void CryPointerScanWindow::PointerScanRightClick(Bar& pBar)
{
	
}

// Opens the new pointer scan window.
void CryPointerScanWindow::NewPointerScanClicked()
{
	CryPointerScanSettings* cpss = new CryPointerScanSettings(CrySearchIml::PointerScanSmall());
	cpss->Execute();
	delete cpss;
}