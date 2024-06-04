
#include "../injlib/injlib.h"
#include <strsafe.h>
#include "resource.h"

//////////////////////////////////////////////////////////////////////////
// DriverEntry and DriverDestroy.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
DriverDestroy(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	PsRemoveLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, TRUE);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\BlueStreetDriver");

	IoDeleteSymbolicLink(&symLink);

	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

	if (deviceObject != NULL)
	{
		IoDeleteDevice(deviceObject);
	}

	InjDestroy();
}

NTSTATUS DriverCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
			
NTSTATUS DriverDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject);
	
	auto stack = IoGetCurrentIrpStackLocation(Irp); // IOC_STACK_LOCATION*
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {

	case IOCTL_BLUESTREET_SEND_DATA:
	{
		auto pData = (sMSG*)stack->Parameters.DeviceIoControl.Type3InputBuffer;

		NTSTATUS Status = InjUpdateSettings(pData, stack);

		if (!NT_SUCCESS(Status)) {
			Irp->IoStatus.Status = Status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Status;
		}
		break;
	}
	default:
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

extern "C" 
NTSTATUS
NTAPI
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{

	NTSTATUS Status;

	DriverObject->DriverUnload = &DriverDestroy;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\BlueStreetDriver");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		InjDbgPrint("Failed to create device object (0x%08X)\n", status);
		return status;
	}

	// Create Symbolic link for the Device which is accessible from user-mode
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\BlueStreetDriver");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		InjDbgPrint("Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	InjInitialize(DriverObject, RegistryPath, InjMethodThunk);

	//
	// Install CreateProcess and LoadImage notification routines.
	//

	Status = PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, FALSE);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = PsSetLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);

	if (!NT_SUCCESS(Status))
	{
		PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, TRUE);
		return Status;
	}

	return STATUS_SUCCESS;
}

