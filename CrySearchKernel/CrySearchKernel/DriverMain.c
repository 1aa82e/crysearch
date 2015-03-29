#include <ntddk.h>
#include <windef.h>

UNICODE_STRING deviceString;
PVOID deviceStringPtr = NULL;
DRIVER_INITIALIZE DriverEntry;

// ----------------------------------------------------------------------------------------------

// IO Control dispatch routine.
NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	switch (Irp->Flags)
	{

	}
}

// ----------------------------------------------------------------------------------------------

// IRP creation service routine.
NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP closure service routine.
NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// Driver unload routine.
void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	DWORD appname[] = { 0x53797243, 0x63726165, 0x68 }; //"CrySearch"
	DbgPrint("Unloading %S driver...\r\n", (char*)appname);
	IoDeleteSymbolicLink(&deviceString);
	ExFreePool(deviceStringPtr);
	IoDeleteDevice(DriverObject->DeviceObject);
}

// Driver entrypoint routine.
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS retVal;
	UNICODE_STRING driverString;
	HANDLE reg = NULL;
	PDEVICE_OBJECT devObj;
	PVOID driverStrPtr = NULL;

	// Start loading the driver by reading the registry path.
	DWORD author[] = { 0x6c6f7665, 0x6f697475, 0x3633356e, 0x0 }; //"evolution536"
	DWORD appname[] = { 0x53797243, 0x63726165, 0x68 }; //"CrySearch"
	DbgPrint("Loading %S driver by %S...\r\n", (char*)appname, (char*)author);
	if (RegistryPath)
	{
		DbgPrint("Registry path: %S\r\n", RegistryPath->Buffer);
		InitializeObjectAttributes(&oa, RegistryPath, OBJ_KERNEL_HANDLE, NULL, NULL);
		retVal = ZwOpenKey(&reg, KEY_QUERY_VALUE, &oa);
		if (retVal == STATUS_SUCCESS)
		{
			UNICODE_STRING a_value;
			UNICODE_STRING b_value;
			ULONG ActualSize;
			PKEY_VALUE_PARTIAL_INFORMATION keybuf_a;
			PKEY_VALUE_PARTIAL_INFORMATION keybuf_b;
			
			driverStrPtr = ExAllocatePool(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100);
			deviceStringPtr = ExAllocatePool(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100);

			keybuf_a = driverStrPtr;
			keybuf_b = deviceStringPtr;
			
			RtlInitUnicodeString(&a_value, L"A");
			RtlInitUnicodeString(&b_value, L"B");

			// Query the driver string value.
			if (retVal = ZwQueryValueKey(reg, &a_value, KeyValuePartialInformation, keybuf_a, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize) == STATUS_SUCCESS)
			{
				// Query the device string value.
				retVal = ZwQueryValueKey(reg, &b_value, KeyValuePartialInformation, keybuf_b, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize);
			}
			
			// Continue if the key reads were succesful.
			if (retVal == STATUS_SUCCESS)
			{
				RtlInitUnicodeString(&driverString, (PCWSTR)keybuf_a->Data);
				RtlInitUnicodeString(&deviceString, (PCWSTR)keybuf_b->Data);
				DbgPrint("Driver String: %S\r\n", driverString.Buffer);
				DbgPrint("Device String: %S\r\n", deviceString.Buffer);
				ZwClose(reg);
			}
			else
			{
				DbgPrint("The RegistryPath could not be read\r\n");
				ExFreePool(keybuf_a);
				ExFreePool(keybuf_b);
				ZwClose(reg);
				return STATUS_UNSUCCESSFUL;
			}
		}
		else
		{
			DbgPrint("Failed to open the RegistryPath key.\r\n");
			return STATUS_UNSUCCESSFUL;
		}

		// Create the device driver object.
		retVal = IoCreateDevice(DriverObject, 0, &driverString, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
		if (retVal != STATUS_SUCCESS)
		{
			DbgPrint("The device driver object could not be created.\r\n");
			ExFreePool(driverStrPtr);
			ExFreePool(deviceStringPtr);
			return retVal;
		}

		// Create a symbolic link for user mode applications.
		retVal = IoCreateSymbolicLink(&deviceString, &driverString);
		if (retVal != STATUS_SUCCESS)
		{
			DbgPrint("Failed to create the driver name symbolic link.\r\n");
			IoDeleteDevice(devObj);
			ExFreePool(driverStrPtr);
			ExFreePool(deviceStringPtr);
			return retVal;
		}

		// Wire up IRP handles to driver routines.
		DriverObject->DriverUnload = UnloadDriver;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

		// Free used resources. Don't free the device string, it is necessary to unload the driver.
		if (driverStrPtr)
		{
			ExFreePool(driverStrPtr);
		}

		DbgPrint("%S driver loaded!\r\n", (char*)appname);
		return retVal;
	}
}