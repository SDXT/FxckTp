#include "ntddk.h"
#include <windef.h>
#include <stdlib.h>
#include "dbghelp.h"
#include "Win7x64Drv.h"


extern POBJECT_TYPE *IoDriverObjectType;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString);
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);
VOID DriverUnload(PDRIVER_OBJECT pDriverObj);
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp);

ULONG64 GetSystemModuleBase(char* lpModuleName)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return 0;
		Result = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			kfree(pBuffer);
			return 0;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	ModuleCount = pSystemModuleInformation->ModuleCount;

	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].ImageBase) >(ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].PathLength;
			if (_stricmp(pDrvName, lpModuleName) == 0)
				return (ULONG64)pSystemModuleInformation->Module[i].ImageBase;
		}
	}
	kfree(pBuffer);
	return 0;
}
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;    
	PDEVICE_OBJECT pDevObj;
	
    //Create dispatch points for device control, create, close.
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0,&ustrDevName, FILE_DEVICE_UNKNOWN,0,FALSE,&pDevObj);

	if(!NT_SUCCESS(status))
	{
		return status;
	}
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);  
	if(!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);  
		return status;
	}
	ULONG64 ACEDriver = GetSystemModuleBase("ACE-BASE.sys");
	
	if (ACEDriver)
	{
		KIRQL irql = WPOFFx64();
		memset(ACEDriver + 0x91931, 0, 0x20);
		memset(ACEDriver + 0x91911, 0, 0x20);
		memset(ACEDriver + 0x918D1, 0, 0x20);
		memset(ACEDriver + 0xDFEE, 0x90, 3);
		WPONx64(irql);
	}
	
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{	
	UNICODE_STRING strLink;
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	switch(uIoControlCode)
	{
		
	}
	if(status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}