#include "injlib.h"

#include <ntimage.h>

#if defined(_M_AMD64) || defined(_M_ARM64)
# define INJ_CONFIG_SUPPORTS_WOW64
#endif


//////////////////////////////////////////////////////////////////////////
// ke.h
//////////////////////////////////////////////////////////////////////////

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(NTAPI* PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

typedef
VOID
(NTAPI* PKKERNEL_ROUTINE)(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
	);

typedef
VOID
(NTAPI* PKRUNDOWN_ROUTINE) (
	_In_ PKAPC Apc
	);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PETHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

NTKERNELAPI
BOOLEAN
NTAPI
KeAlertThread(
	_Inout_ PKTHREAD Thread,
	_In_ KPROCESSOR_MODE AlertMode
);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(
	_In_ KPROCESSOR_MODE AlertMode
);

//////////////////////////////////////////////////////////////////////////
// ps.h
//////////////////////////////////////////////////////////////////////////

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
	_In_ PEPROCESS Process
);

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
	_In_ PEPROCESS Process
);

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(
	_In_ PEPROCESS Process
);

NTKERNELAPI
USHORT
NTAPI
PsWow64GetProcessMachine(
	_In_ PEPROCESS Process
);

//////////////////////////////////////////////////////////////////////////
// ntrtl.h
//////////////////////////////////////////////////////////////////////////

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

NTSYSAPI
NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
	_In_ ULONG Flags,
	_In_ PUNICODE_STRING StringIn,
	_Out_ PUNICODE_STRING StringOut
);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
	_In_ PVOID BaseOfImage,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
);

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define INJ_MEMORY_TAG ' jnI'

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _INJ_SYSTEM_DLL
{
	INJ_NOTHING_LOADED = 0x0000,
	INJ_SYSARM32_NTDLL_LOADED = 0x0001,
	INJ_SYCHPE32_NTDLL_LOADED = 0x0002,
	INJ_SYSWOW64_NTDLL_LOADED = 0x0004,
	INJ_SYSTEM32_NTDLL_LOADED = 0x0008,
	INJ_SYSTEM32_WOW64_LOADED = 0x0010,
	INJ_SYSTEM32_WOW64WIN_LOADED = 0x0020,
	INJ_SYSTEM32_WOW64CPU_LOADED = 0x0040,
	INJ_SYSTEM32_WOWARMHW_LOADED = 0x0080,
	INJ_SYSTEM32_XTAJIT_LOADED = 0x0100,
} INJ_SYSTEM_DLL;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _INJ_SYSTEM_DLL_DESCRIPTOR
{
	UNICODE_STRING  DllPath;
	INJ_SYSTEM_DLL  Flag;
} INJ_SYSTEM_DLL_DESCRIPTOR, * PINJ_SYSTEM_DLL_DESCRIPTOR;

typedef struct _INJ_THUNK
{
	PVOID           Buffer;
	USHORT          Length;
} INJ_THUNK, * PINJ_THUNK;

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjpQueueApc(
	_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

VOID
NTAPI
InjpInjectApcNormalRoutine(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

VOID
NTAPI
InjpInjectApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);

//
// reparse.c
//

NTSTATUS
NTAPI
SimRepInitialize(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

//////////////////////////////////////////////////////////////////////////
// Private constant variables.
//////////////////////////////////////////////////////////////////////////

ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");

//
// Paths can have format "\Device\HarddiskVolume3\Windows\System32\ntdll.dll",
// so only the end of the string is compared.
//

INJ_SYSTEM_DLL_DESCRIPTOR InjpSystemDlls[] = {
  { RTL_CONSTANT_STRING(L"\\SysArm32\\ntdll.dll"),    INJ_SYSARM32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\SyChpe32\\ntdll.dll"),    INJ_SYCHPE32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\SysWow64\\ntdll.dll"),    INJ_SYSWOW64_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\ntdll.dll"),    INJ_SYSTEM32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64.dll"),    INJ_SYSTEM32_WOW64_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64win.dll"), INJ_SYSTEM32_WOW64WIN_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64cpu.dll"), INJ_SYSTEM32_WOW64CPU_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\wowarmhw.dll"), INJ_SYSTEM32_WOWARMHW_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\xtajit.dll"),   INJ_SYSTEM32_XTAJIT_LOADED   },
};

//
// ;++
// ;
// ; VOID
// ; NTAPI
// ; ApcNormalRoutine(
// ;   _In_ PVOID NormalContext,
// ;   _In_ PVOID SystemArgument1,
// ;   _In_ PVOID SystemArgument2
// ;   )
// ;
// ; Routine Description:
// ;
// ;    This routine loads DLL specified in the NormalContext.
// ;
// ;    If native process is being injected, this function is called
// ;    from the ntdll.dll!KiUserApcDispatcher routine.
// ;
// ;    If Wow64 process is being injected, the following code-flow
// ;    is responsible for reaching this function:
// ;
// ;    - wow64.dll!Wow64ApcRoutine (set by PsWrapApcWow64Thread):
// ;      - Puts NormalRoutine, NormalContext, SystemArgument1 and
// ;        SystemArgument2 on the top of the stack, sets EIP to
// ;        KiUserApcDispatcher of Wow64 ntdll.dll.
// ;    - ntdll.dll!KiUserApcDispatcher (note this is Wow64 ntdll.dll)
// ;      - Pops NormalRoutine - our ApcNormalRoutine - from the stack
// ;        and calls it (note that NormalCountext, SystemArgument1 and
// ;        SystemArgument2 remain on the stack).
// ;
// ;    The shellcode is equivalent to this code - regardless of the
// ;    architecture:
// ;
// ;    VOID
// ;    NTAPI
// ;    ApcNormalRoutine(
// ;        _In_ PVOID NormalContext,    // LdrLoadDll routine address
// ;        _In_ PVOID SystemArgument1,  // DllPath
// ;        _In_ PVOID SystemArgument2   // DllPath length
// ;        )
// ;    {
// ;        UNICODE_STRING DllName;
// ;        PVOID          BaseAddress;
// ;
// ;        DllName.Length        = (USHORT)SystemArgument2;
// ;        DllName.MaximumLength = (USHORT)SystemArgument2;
// ;        DllName.Buffer        = (PWSTR) SystemArgument1;
// ;
// ;        ((PLDRLOADDLL_ROUTINE)NormalContext)(0, 0, &DllName, &BaseAddress);
// ;    }
// ;
// ;    // See: https://gcc.godbolt.org/z/1DDtuW
// ;
// ; Arguments:
// ;
// ;    NormalContext   - LdrLoadDll routine address.
// ;    SystemArgument1 - DLL path.
// ;    SystemArgument2 - Length of DLL path.
// ;
// ; Return Value:
// ;
// ;    None.
// ;
// ;--
//

UCHAR InjpThunkX86[] = {              //
  0x83, 0xec, 0x08,                   // sub    esp,0x8
  0x0f, 0xb7, 0x44, 0x24, 0x14,       // movzx  eax,[esp + 0x14]
  0x66, 0x89, 0x04, 0x24,             // mov    [esp],ax
  0x66, 0x89, 0x44, 0x24, 0x02,       // mov    [esp + 0x2],ax
  0x8b, 0x44, 0x24, 0x10,             // mov    eax,[esp + 0x10]
  0x89, 0x44, 0x24, 0x04,             // mov    [esp + 0x4],eax
  0x8d, 0x44, 0x24, 0x14,             // lea    eax,[esp + 0x14]
  0x50,                               // push   eax
  0x8d, 0x44, 0x24, 0x04,             // lea    eax,[esp + 0x4]
  0x50,                               // push   eax
  0x6a, 0x00,                         // push   0x0
  0x6a, 0x00,                         // push   0x0
  0xff, 0x54, 0x24, 0x1c,             // call   [esp + 0x1c]
  0x83, 0xc4, 0x08,                   // add    esp,0x8
  0xc2, 0x0c, 0x00,                   // ret    0xc
};                                    //

UCHAR InjpThunkX64[] = {              //
  0x48, 0x83, 0xec, 0x38,             // sub    rsp,0x38
  0x48, 0x89, 0xc8,                   // mov    rax,rcx
  0x66, 0x44, 0x89, 0x44, 0x24, 0x20, // mov    [rsp+0x20],r8w
  0x66, 0x44, 0x89, 0x44, 0x24, 0x22, // mov    [rsp+0x22],r8w
  0x4c, 0x8d, 0x4c, 0x24, 0x40,       // lea    r9,[rsp+0x40]
  0x48, 0x89, 0x54, 0x24, 0x28,       // mov    [rsp+0x28],rdx
  0x4c, 0x8d, 0x44, 0x24, 0x20,       // lea    r8,[rsp+0x20]
  0x31, 0xd2,                         // xor    edx,edx
  0x31, 0xc9,                         // xor    ecx,ecx
  0xff, 0xd0,                         // call   rax
  0x48, 0x83, 0xc4, 0x38,             // add    rsp,0x38
  0xc2, 0x00, 0x00,                   // ret    0x0
};                                    //


//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

LIST_ENTRY      InjInfoListHead;

INJ_METHOD      InjMethod;

//UNICODE_STRING  InjDllPath[InjArchitectureMax][2];
UNICODE_STRING  InjPath[InjArchitectureMax];
UNICODE_STRING  InjDlls;

INJ_THUNK       InjThunk[InjArchitectureMax] = {
  { InjpThunkX86,   sizeof(InjpThunkX86)   },
  { InjpThunkX64,   sizeof(InjpThunkX64)   },
};

BOOLEAN         InjIsWindows7;

//////////////////////////////////////////////////////////////////////////
// Helper functions.
//////////////////////////////////////////////////////////////////////////

PVOID
NTAPI
RtlxFindExportedRoutineByName(
	_In_ PVOID DllBase,
	_In_ PANSI_STRING ExportName
)
{
	//
	// RtlFindExportedRoutineByName is not exported by ntoskrnl until Win10.
	// Following code is borrowed from ReactOS.
	//

	PULONG NameTable;
	PUSHORT OrdinalTable;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	LONG Low = 0, Mid = 0, High, Ret;
	USHORT Ordinal;
	PVOID Function;
	ULONG ExportSize;
	PULONG ExportTable;

	//
	// Get the export directory.
	//

	ExportDirectory = RtlImageDirectoryEntryToData(DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (!ExportDirectory)
	{
		return NULL;
	}

	//
	// Setup name tables.
	//

	NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
	OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

	//
	// Do a binary search.
	//

	High = ExportDirectory->NumberOfNames - 1;
	while (High >= Low)
	{
		//
		// Get new middle value.
		//

		Mid = (Low + High) >> 1;

		//
		// Compare name.
		//

		Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);
		if (Ret < 0)
		{
			//
			// Update high.
			//
			High = Mid - 1;
		}
		else if (Ret > 0)
		{
			//
			// Update low.
			//
			Low = Mid + 1;
		}
		else
		{
			//
			// We got it.
			//
			break;
		}
	}

	//
	// Check if we couldn't find it.
	//

	if (High < Low)
	{
		return NULL;
	}

	//
	// Otherwise, this is the ordinal.
	//

	Ordinal = OrdinalTable[Mid];

	//
	// Validate the ordinal.
	//

	if (Ordinal >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	}

	//
	// Resolve the address and write it.
	//

	ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
	Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

	//
	// We found it!
	//

	NT_ASSERT(
		(Function < (PVOID)ExportDirectory) ||
		(Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
	);

	return Function;
}

BOOLEAN
NTAPI
RtlxSuffixUnicodeString(
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
)
{
	//
	// RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
	//

	return String2->Length >= String1->Length &&
		RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - String1->Length) / sizeof(WCHAR),
			String1->Length / sizeof(WCHAR),
			String1->Buffer,
			String1->Length / sizeof(WCHAR),
			CaseInSensitive) == 0;

}

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjpQueueApc(
	_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	//
	// Allocate memory for the KAPC structure.
	//

	PKAPC Apc = ExAllocatePoolWithTag(NonPagedPoolNx,
		sizeof(KAPC),
		INJ_MEMORY_TAG);

	if (!Apc)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Initialize and queue the APC.
	//

	KeInitializeApc(Apc,                                  // Apc
		PsGetCurrentThread(),                 // Thread
		OriginalApcEnvironment,               // Environment
		&InjpInjectApcKernelRoutine,          // KernelRoutine
		NULL,                                 // RundownRoutine
		NormalRoutine,                        // NormalRoutine
		ApcMode,                              // ApcMode
		NormalContext);                       // NormalContext

	BOOLEAN Inserted = KeInsertQueueApc(Apc,              // Apc
		SystemArgument1,  // SystemArgument1
		SystemArgument2,  // SystemArgument2
		0);               // Increment

	if (!Inserted)
	{
		ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

VOID
NTAPI
InjpInjectApcNormalRoutine(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PINJ_INJECTION_INFO InjectionInfo = NormalContext;
	InjInject(InjectionInfo);
}

VOID
NTAPI
InjpInjectApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//
	// Common kernel routine for both user-mode and
	// kernel-mode APCs queued by the InjpQueueApc
	// function.  Just release the memory of the APC
	// structure and return back.
	//

	ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
}

NTSTATUS
NTAPI
InjpInject(
	_In_ PINJ_INJECTION_INFO InjectionInfo,
	_In_ INJ_ARCHITECTURE Architecture,
	_In_ HANDLE SectionHandle,
	_In_ SIZE_T SectionSize,
	_In_ PUNICODE_STRING usDllPath
)
{
	NTSTATUS Status;

	//
	// First, map this section with read-write access.
	//

	PVOID SectionMemoryAddress = NULL;
	Status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		SectionSize,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	//
	// Code of the APC routine (ApcNormalRoutine defined in the
	// "shellcode" above) starts at the SectionMemoryAddress.
	// Copy the shellcode to the allocated memory.
	//

	PVOID ApcRoutineAddress = SectionMemoryAddress;
	RtlCopyMemory(ApcRoutineAddress,
		InjThunk[Architecture].Buffer,
		InjThunk[Architecture].Length);

	//
	// Fill the data of the ApcContext.
	//

	PWCHAR DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + InjThunk[Architecture].Length);
	RtlCopyMemory(DllPath,
		usDllPath->Buffer,
		usDllPath->Length);

	//
	// Unmap the section and map it again, but now
	// with read-execute (no write) access.
	//

	ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);

	SectionMemoryAddress = NULL;
	Status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	//
	// Reassign remapped address.
	//

	ApcRoutineAddress = SectionMemoryAddress;
	DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + InjThunk[Architecture].Length);

	PVOID ApcContext = (PVOID)InjectionInfo->LdrLoadDllRoutineAddress;
	PVOID ApcArgument1 = (PVOID)DllPath;
	PVOID ApcArgument2 = (PVOID)usDllPath->Length;

	InjDbgPrint("[injlib]: Inject Architecture: %d\n", Architecture);
	InjDbgPrint("[injlib]: Inject DllPath: '%ws'\n", DllPath);

#if defined(INJ_CONFIG_SUPPORTS_WOW64)

	if (PsGetProcessWow64Process(PsGetCurrentProcess()))
	{
		//
		// PsWrapApcWow64Thread essentially assigns wow64.dll!Wow64ApcRoutine
		// to the NormalRoutine.  This Wow64ApcRoutine (which is 64-bit code)
		// in turn calls KiUserApcDispatcher (in 32-bit ntdll.dll) which finally
		// calls our provided ApcRoutine.
		//

		PsWrapApcWow64Thread(&ApcContext, &ApcRoutineAddress);
	}

#endif

	PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutineAddress;

	Status = InjpQueueApc(UserMode,
		ApcRoutine,
		ApcContext,
		ApcArgument1,
		ApcArgument2);

	if (!NT_SUCCESS(Status))
	{
		//
		// If injection failed for some reason, unmap the section.
		//

		ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);
	}

Exit:
	return Status;
}

NTSTATUS
NTAPI
InjpInjectX64NoThunk(
	_In_ PINJ_INJECTION_INFO InjectionInfo,
	_In_ INJ_ARCHITECTURE Architecture,
	_In_ HANDLE SectionHandle,
	_In_ SIZE_T SectionSize
)
{
	NT_ASSERT(InjectionInfo->LdrLoadDllRoutineAddress);
	NT_ASSERT(Architecture == InjArchitectureX64);

	UNREFERENCED_PARAMETER(Architecture);

	NTSTATUS Status;

	PVOID SectionMemoryAddress = NULL;
	Status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	//
	// Create the UNICODE_STRING structure and fill out the
	// full path of the DLL.
	//

			//PUNICODE_STRING DllPath = (PUNICODE_STRING)(SectionMemoryAddress);
			//PWCHAR DllPathBuffer = (PWCHAR)((PUCHAR)DllPath + sizeof(UNICODE_STRING));

			//RtlCopyMemory(DllPathBuffer,
			//	InjDllPath[Architecture][0].Buffer,
			//	InjDllPath[Architecture][0].Length);

			//RtlInitUnicodeString(DllPath, DllPathBuffer);

			//Status = InjpQueueApc(UserMode,
			//	(PKNORMAL_ROUTINE)(ULONG_PTR)InjectionInfo->LdrLoadDllRoutineAddress,
			//	NULL,     // Translates to 1st param. of LdrLoadDll (SearchPath)
			//	NULL,     // Translates to 2nd param. of LdrLoadDll (DllCharacteristics)
			//	DllPath); // Translates to 3rd param. of LdrLoadDll (DllName)



	//
	// 4th param. of LdrLoadDll (BaseAddress) is actually an output parameter.
	//
	// When control is transferred to the KiUserApcDispatcher routine of the
	// 64-bit ntdll.dll, the RSP points to the CONTEXT structure which might
	// be eventually provided to the ZwContinue function (in case this APC
	// dispatch will be routed to the Wow64 subsystem).
	//
	// Also, the value of the RSP register is moved to the R9 register before
	// calling the KiUserCallForwarder function.  The KiUserCallForwarder
	// function actually passes this value of the R9 register down to the
	// NormalRoutine as a "hidden 4th parameter".
	//
	// Because LdrLoadDll writes to the provided address, it'll actually
	// result in overwrite of the CONTEXT.P1Home field (the first field of
	// the CONTEXT structure).
	//
	// Luckily for us, this field is only used in the very early stage of
	// the APC dispatch and can be overwritten without causing any troubles.
	//
	// For excellent explanation, see:
	// https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-2
	//

Exit:
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////


NTSTATUS
NTAPI
InjUpdateSettings(
	_In_ PsMSG RecivedData,
	_In_ PIO_STACK_LOCATION stack
)
{

	auto status = STATUS_SUCCESS;
	if (RecivedData != NULL && stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(sMSG))
	{
		InjDbgPrint("Received StringData:\n");
		ULONG Flags = RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE | RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING;

		UNICODE_STRING Dlls;
		UNICODE_STRING DIR_X64;
		UNICODE_STRING DIR_X86;

		Dlls.Buffer = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (wcslen(RecivedData->Dlls) + 1) * sizeof(WCHAR), 'DIR');
		DIR_X64.Buffer = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (wcslen(RecivedData->Path) + wcslen(L"\\x64") + 1) * sizeof(WCHAR), 'DIR'); 
		DIR_X86.Buffer = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (wcslen(RecivedData->Path) + wcslen(L"\\x32") + 1) * sizeof(WCHAR), 'DIR'); 

		if (Dlls.Buffer == NULL || DIR_X64.Buffer == NULL || DIR_X86.Buffer == NULL)
		{
			if(Dlls.Buffer != NULL)
				ExFreePool(Dlls.Buffer);
			if(DIR_X64.Buffer != NULL)
				ExFreePool(DIR_X64.Buffer);
			if (DIR_X86.Buffer != NULL)
				ExFreePool(DIR_X86.Buffer);
			return STATUS_INVALID_PARAMETER;
		}
			
		{
			wcscpy_s(Dlls.Buffer, wcslen(RecivedData->Dlls) + 1, RecivedData->Dlls);
			Dlls.Length = wcslen(Dlls.Buffer) * sizeof(WCHAR);
			Dlls.MaximumLength = Dlls.Length + sizeof(WCHAR);

			status = RtlDuplicateUnicodeString(Flags, &Dlls, &InjDlls);
			if (!NT_SUCCESS(status))
				return status;

			ExFreePool(Dlls.Buffer);
		}
			
		{
			wcscpy_s(DIR_X64.Buffer, wcslen(RecivedData->Path) + 1, RecivedData->Path);
			wcscat_s(DIR_X64.Buffer, wcslen(RecivedData->Path) + wcslen(L"\\x64") + 1, L"\\x64");
			DIR_X64.Length = wcslen(DIR_X64.Buffer) * sizeof(WCHAR);
			DIR_X64.MaximumLength = DIR_X64.Length + sizeof(WCHAR);
			
			status = RtlDuplicateUnicodeString(Flags, &DIR_X64, &InjPath[InjArchitectureX64]);
			if (!NT_SUCCESS(status))
				return status;


			ExFreePool(DIR_X64.Buffer);
		}

		
		{
			wcscpy_s(DIR_X86.Buffer, wcslen(RecivedData->Path) + 1, RecivedData->Path);
			wcscat_s(DIR_X86.Buffer, wcslen(RecivedData->Path) + wcslen(L"\\x32") + 1, L"\\x32");
			DIR_X86.MaximumLength = DIR_X64.MaximumLength;
			DIR_X86.Length = DIR_X64.Length;

			status = RtlDuplicateUnicodeString(Flags, &DIR_X86, &InjPath[InjArchitectureX86]);
			if (!NT_SUCCESS(status))
				return status;

			ExFreePool(DIR_X86.Buffer);
		}

	}
	else {
		InjDbgPrint("Error: Invalid or insufficient input buffer\n");
		status = STATUS_INVALID_PARAMETER;
	}

	InjDbgPrint("[injlib]: InjDlls: %wZ\n", InjDlls);
	InjDbgPrint("[injlib]: InjPath[InjArchitectureX64]: %wZ\n", InjPath[InjArchitectureX64]);
	InjDbgPrint("[injlib]: InjPath[InjArchitectureX86]: %wZ\n", InjPath[InjArchitectureX86]);

	return status;
}


NTSTATUS
NTAPI
InjInitialize(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath,
	_In_ INJ_METHOD _InjMethod
)
{

	InitializeListHead(&InjInfoListHead);

	NTSTATUS Status = STATUS_SUCCESS;

	//
	// Check if we're running on Windows 7.
	//

	RTL_OSVERSIONINFOW VersionInformation = { 0 };
	VersionInformation.dwOSVersionInfoSize = sizeof(VersionInformation);
	RtlGetVersion(&VersionInformation);

	if (VersionInformation.dwMajorVersion == 6 &&
		VersionInformation.dwMinorVersion == 1)
	{
		InjDbgPrint("[injlib]: Current system is Windows 7\n");
		InjIsWindows7 = TRUE;
	}

	//
	// Default setting of the injection of Wow64 processes.
	//

#if defined(INJ_CONFIG_SUPPORTS_WOW64)
	InjMethod = _InjMethod;

#  if !defined(_M_AMD64)
	//
	// Thunkless method is available on x64.
	//

	if (InjMethod == InjMethodThunkless)
	{
		InjMethod = InjMethodThunk;
	}
#  endif

#else
	InjMethod = InjMethodThunk;
#endif

	InjDbgPrint("[injlib]: InjMethod: '%s'\n",
		InjMethod == InjMethodThunk ? "InjMethodThunk" :
		InjMethod == InjMethodThunkless ? "InjMethodThunkLess" :
		InjMethod == InjMethodWow64LogReparse ? "InjMethodWow64LogReparse" :
		"UNKNOWN"
	);

	if (InjMethod == InjMethodWow64LogReparse)
	{
		Status = SimRepInitialize(DriverObject, RegistryPath);
	}

	return Status;

Error:
	InjDestroy();
	return Status;
}

VOID
NTAPI
InjDestroy(
	VOID
)
{
	//
	// Release memory of all injection-info entries.
	//

	PLIST_ENTRY NextEntry = InjInfoListHead.Flink;

	while (NextEntry != &InjInfoListHead)
	{
		PINJ_INJECTION_INFO InjectionInfo = CONTAINING_RECORD(NextEntry,
			INJ_INJECTION_INFO,
			ListEntry);
		NextEntry = NextEntry->Flink;

		ExFreePoolWithTag(InjectionInfo, INJ_MEMORY_TAG);
	}

	//
	// Release memory of all buffers.
	//

	for (ULONG Architecture = 0; Architecture < InjArchitectureMax; Architecture += 1)
	{
		//RtlFreeUnicodeString(&InjDllPath[Architecture]); TODO
	}
}

BOOLEAN ContainsSubstring(PCUNICODE_STRING str, PCWSTR substr) {
	PWCHAR buffer = str->Buffer;
	ULONG length = str->Length / sizeof(WCHAR);

	PWCHAR result = wcsstr(buffer, substr);

	// ≈сли подстрока найдена и начинаетс€ с начала строки или после пробела
	return result && (result == buffer || *(result - 1) == L' ');
}



NTSTATUS
NTAPI
InjCreateInjectionInfo(
	_In_opt_ PINJ_INJECTION_INFO* InjectionInfo,
	_In_ HANDLE ProcessId,
	_In_opt_ PCUNICODE_STRING CommandLine,
	_In_opt_ PCUNICODE_STRING ImageFileName
)
{
	BOOLEAN containsSubstring = ContainsSubstring(CommandLine, L"-dxvk");
	BOOLEAN isDxvkConfigPresent = FALSE;
	if (!containsSubstring)
	{
		PUNICODE_STRING exePath = ImageFileName;
		WCHAR confPathBuffer[512];
		UNICODE_STRING confPath;

		RtlCopyMemory(confPathBuffer, exePath->Buffer, exePath->Length);
		confPathBuffer[exePath->Length / sizeof(WCHAR)] = L'\0';
		WCHAR* lastSlash = wcsrchr(confPathBuffer, L'\\');
		if (lastSlash)
		{
			wcscpy(lastSlash + 1, L"dxvk.conf");
		}
		RtlInitUnicodeString(&confPath, confPathBuffer);

		UNICODE_STRING Path;
		UNICODE_STRING Dlls;
		RtlInitUnicodeString(&Path, NULL);
		RtlInitUnicodeString(&Dlls, NULL);

		NTSTATUS status = ReadDxvkConfigFile(&isDxvkConfigPresent, &confPath, &Path, &Dlls);

		if (NT_SUCCESS(status))
		{
			ULONG Flags = RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE | RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING;

			UNICODE_STRING PathX64, PathX86;
			WCHAR PathX64Buffer[512], PathX86Buffer[512];

			// ‘ормируем строку дл€ PathX64
			wcsncpy(PathX64Buffer, Path.Buffer, Path.Length / sizeof(WCHAR));
			PathX64Buffer[Path.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate the string
			wcscat(PathX64Buffer, L"\\x64");
			RtlInitUnicodeString(&PathX64, PathX64Buffer);

			// ‘ормируем строку дл€ PathX86
			wcsncpy(PathX86Buffer, Path.Buffer, Path.Length / sizeof(WCHAR));
			PathX86Buffer[Path.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate the string
			wcscat(PathX86Buffer, L"\\x32");
			RtlInitUnicodeString(&PathX86, PathX86Buffer);

			NTSTATUS statusX64 = RtlDuplicateUnicodeString(Flags, &PathX64, &InjPath[InjArchitectureX64]);
			NTSTATUS statusX86 = RtlDuplicateUnicodeString(Flags, &PathX86, &InjPath[InjArchitectureX86]);
			NTSTATUS statusDlls = RtlDuplicateUnicodeString(Flags, &Dlls, &InjDlls);

			if (!NT_SUCCESS(statusX64) || !NT_SUCCESS(statusX86) || !NT_SUCCESS(statusDlls))
			{
				InjDbgPrint("Failed to duplicate unicode strings for injection paths or DLLs\n");
				return status;
			}

			InjDbgPrint("\tInjPath[InjArchitectureX64]: %wZ\n", &InjPath[InjArchitectureX64]);
			InjDbgPrint("\tInjPath[InjArchitectureX86]: %wZ\n", &InjPath[InjArchitectureX86]);
			InjDbgPrint("\tInjDlls: %wZ\n", &InjDlls);

		}
		else
		{
			InjDbgPrint("\tReadDxvkConfigFile failed with status: 0x%08X\n", status);
			return STATUS_SUCCESS;
		}
	}
	
	for (ULONG Architecture = 0; Architecture < InjArchitectureMax; Architecture++)
	{
		if (InjPath[Architecture].Length == 0)
		{
			return STATUS_SUCCESS;
		}
	}

	if (InjDlls.Length == 0)
	{
		return STATUS_SUCCESS;
	}

	BOOLEAN child_process = FALSE;
	for (PLIST_ENTRY currentEntry = InjInfoListHead.Flink; currentEntry != &InjInfoListHead; currentEntry = currentEntry->Flink)
	{
		// ѕолучение указател€ на структуру INJ_INJECTION_INFO из элемента списка
		PINJ_INJECTION_INFO injectionInfo = CONTAINING_RECORD(currentEntry, INJ_INJECTION_INFO, ListEntry);

		// “еперь у вас есть доступ к данным в структуре INJ_INJECTION_INFO через переменную injectionInfo

		// Ќапример, вы можете вывести ProcessId
		InjDbgPrint("ProcessId: %lu\n", (ULONG)injectionInfo->ProcessId);
		InjDbgPrint("injectionInfo->Settings->Dlls: %wZ\n", injectionInfo->Dlls);
		for (size_t i = 0; i < InjArchitectureMax; i++)
		{
			InjDbgPrint("injectionInfo->Settings->Path[i]: %wZ\n", injectionInfo->Path[i]);
		}
		
		if (PsGetProcessId(IoGetCurrentProcess()) == injectionInfo->ProcessId) {
			
			child_process = TRUE;
			break;
		}
		// »ли выполнить другие операции с данными в структуре

		// «десь можно добавить нужную вам обработку
	}
	


	//InjDbgPrint("ProcessId: %lu \t %wZ \tParent PID: %lu\n", (ULONG)ProcessId, CommandLine, (ULONG)parentPid);

	if (child_process)
		InjDbgPrint("[injlib]: Child process parent: %lu", (ULONG)PsGetProcessId(IoGetCurrentProcess()));
	else if (containsSubstring)
		InjDbgPrint("[injlib]: Command line contains '-dxvk': %s\n", containsSubstring ? "TRUE" : "FALSE");
	else if(isDxvkConfigPresent)
		InjDbgPrint("[injlib]: isDxvkConfigPresent\n");
	else 
		return STATUS_SUCCESS;
	/*else if(parentPid == )
	else*/
		


	PINJ_INJECTION_INFO CapturedInjectionInfo;

	if (InjectionInfo && *InjectionInfo)
	{
		CapturedInjectionInfo = *InjectionInfo;
	}
	else
	{
		CapturedInjectionInfo = (PINJ_INJECTION_INFO)ExAllocatePoolWithTag(NonPagedPoolNx,
			sizeof(INJ_INJECTION_INFO),
			INJ_MEMORY_TAG);

		if (!CapturedInjectionInfo)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		if (InjectionInfo)
		{
			*InjectionInfo = CapturedInjectionInfo;
		}
	}

	RtlZeroMemory(CapturedInjectionInfo, sizeof(INJ_INJECTION_INFO));

	CapturedInjectionInfo->ProcessId = ProcessId;
	CapturedInjectionInfo->ForceUserApc = TRUE;
	CapturedInjectionInfo->Method = InjMethod;
	
	ULONG Flags = RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE
		| RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING;

	InjDbgPrint("[injlib]: InjDlls: %wZ\n", InjDlls);
	InjDbgPrint("[injlib]: InjPath[InjArchitectureX64]: %wZ\n", InjPath[InjArchitectureX64]);
	InjDbgPrint("[injlib]: InjPath[InjArchitectureX86]: %wZ\n", InjPath[InjArchitectureX86]);
	
	for (size_t i = 0; i < InjArchitectureMax; i++)
		RtlDuplicateUnicodeString(Flags, &InjPath[i], &CapturedInjectionInfo->Path[i]);
	
	RtlDuplicateUnicodeString(Flags, &InjDlls, &CapturedInjectionInfo->Dlls);

	//CapturedInjectionInfo->Settings = InjectionInfo;
	//CapturedInjectionInfo->CommandLine = CommandLine;
	
	InsertTailList(&InjInfoListHead, &CapturedInjectionInfo->ListEntry);

	return STATUS_SUCCESS;
}

VOID
NTAPI
InjRemoveInjectionInfo(
	_In_ PINJ_INJECTION_INFO InjectionInfo,
	_In_ BOOLEAN FreeMemory
)
{
	RemoveEntryList(&InjectionInfo->ListEntry);

	if (FreeMemory)
	{
		ExFreePoolWithTag(InjectionInfo, INJ_MEMORY_TAG);
	}
}

VOID
NTAPI
InjRemoveInjectionInfoByProcessId(
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN FreeMemory
)
{
	PINJ_INJECTION_INFO InjectionInfo = InjFindInjectionInfo(ProcessId);

	if (InjectionInfo)
	{
		InjRemoveInjectionInfo(InjectionInfo, FreeMemory);
	}
}

PINJ_INJECTION_INFO
NTAPI
InjFindInjectionInfo(
	_In_ HANDLE ProcessId
)
{
	PLIST_ENTRY NextEntry = InjInfoListHead.Flink;

	while (NextEntry != &InjInfoListHead)
	{
		PINJ_INJECTION_INFO InjectionInfo = CONTAINING_RECORD(NextEntry,
			INJ_INJECTION_INFO,
			ListEntry);

		if (InjectionInfo->ProcessId == ProcessId)
		{
			return InjectionInfo;
		}

		NextEntry = NextEntry->Flink;
	}

	return NULL;
}

BOOLEAN
NTAPI
InjCanInject(
	_In_ PINJ_INJECTION_INFO InjectionInfo
)
{
	//
	// DLLs that need to be loaded in the native process
	// (i.e.: x64 process on x64 Windows, x86 process on
	// x86 Windows) before we can safely load our DLL.
	//

	ULONG RequiredDlls = INJ_SYSTEM32_NTDLL_LOADED;

#if defined(INJ_CONFIG_SUPPORTS_WOW64)

	if (PsGetProcessWow64Process(PsGetCurrentProcess()))
	{
		//
		// DLLs that need to be loaded in the Wow64 process
		// before we can safely load our DLL.
		//

		RequiredDlls |= INJ_SYSTEM32_NTDLL_LOADED;
		RequiredDlls |= INJ_SYSTEM32_WOW64_LOADED;
		RequiredDlls |= INJ_SYSTEM32_WOW64WIN_LOADED;

#   if defined (_M_AMD64)

		RequiredDlls |= INJ_SYSTEM32_WOW64CPU_LOADED;
		RequiredDlls |= INJ_SYSWOW64_NTDLL_LOADED;

#   elif defined (_M_ARM64)

		switch (PsWow64GetProcessMachine(PsGetCurrentProcess()))
		{
		case IMAGE_FILE_MACHINE_I386:

			//
			// Emulated x86 processes can load either SyCHPE32\ntdll.dll or
			// SysWOW64\ntdll.dll - depending on whether "hybrid execution
			// mode" is enabled or disabled.
			//
			// PsWow64GetProcessNtdllType(Process) can provide this information,
			// by returning EPROCESS->Wow64Process.NtdllType.  Unfortunatelly,
			// that function is not exported and EPROCESS is not documented.
			//
			// The solution here is to pick the Wow64 NTDLL which is already
			// loaded and set it as "required".
			//

			RequiredDlls |= InjectionInfo->LoadedDlls & (
				INJ_SYSWOW64_NTDLL_LOADED |
				INJ_SYCHPE32_NTDLL_LOADED
				);
			RequiredDlls |= INJ_SYSTEM32_XTAJIT_LOADED;
			break;

		case IMAGE_FILE_MACHINE_ARMNT:
			RequiredDlls |= INJ_SYSARM32_NTDLL_LOADED;
			RequiredDlls |= INJ_SYSTEM32_WOWARMHW_LOADED;
			break;

		case IMAGE_FILE_MACHINE_ARM64:
			break;
		}

#   endif

	}

#endif

	return (InjectionInfo->LoadedDlls & RequiredDlls) == RequiredDlls;
}

NTSTATUS
NTAPI
InjInject(
	_In_ PINJ_INJECTION_INFO InjectionInfo
)
{
	NTSTATUS Status = TRUE;

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	size_t begin = 0;
	size_t dllsLength = InjectionInfo->Dlls.Length / sizeof(WCHAR);
	for (size_t i = 0; i < dllsLength; i++) {
		if (InjDlls.Buffer[i] == L',' || i == dllsLength - 1 ) {

			UNICODE_STRING us;
			RtlInitUnicodeString(&us, InjDlls.Buffer + begin);
			us.Length = (USHORT)((i - begin + ((i == dllsLength - 1) ? 1 : 0) ) * sizeof(WCHAR));

			HANDLE SectionHandle;
			SIZE_T SectionSize = PAGE_SIZE;


			LARGE_INTEGER MaximumSize;
			MaximumSize.QuadPart = SectionSize;
			Status = ZwCreateSection(&SectionHandle,
				GENERIC_READ | GENERIC_WRITE,
				&ObjectAttributes,
				&MaximumSize,
				PAGE_EXECUTE_READWRITE,
				SEC_COMMIT,
				NULL);

			if (!NT_SUCCESS(Status))
			{
				return Status;
			}

			INJ_ARCHITECTURE Architecture = InjArchitectureMax;

			if (InjectionInfo->Method == InjMethodThunk || InjectionInfo->Method == InjMethodWow64LogReparse)
			{

				#if defined(_M_IX86)
					Architecture = InjArchitectureX86;
				#elif defined(_M_AMD64)
					Architecture = PsGetProcessWow64Process(PsGetCurrentProcess()) ? InjArchitectureX86 : InjArchitectureX64;
				#endif

				UNICODE_STRING DllPath;
				RtlInitUnicodeString(&DllPath, NULL);
				DllPath.MaximumLength = InjPath[Architecture].Length + us.Length + sizeof(L"\\") + sizeof(WCHAR);
				DllPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, DllPath.MaximumLength, 'PDLL');

				RtlAppendUnicodeToString(&DllPath, InjectionInfo->Path[Architecture].Buffer);
				RtlAppendUnicodeToString(&DllPath, L"\\");
				RtlAppendUnicodeStringToString(&DllPath, &us);

				NT_ASSERT(Architecture != InjArchitectureMax);

				InjpInject(InjectionInfo,
					Architecture,
					SectionHandle,
					SectionSize,
					&DllPath);

				ExFreePool(DllPath.Buffer);
			}

			ZwClose(SectionHandle);

			if (NT_SUCCESS(Status) && InjectionInfo->ForceUserApc)
			{
				//
				// Sets CurrentThread->ApcState.UserApcPending to TRUE.
				// This causes the queued user APC to be triggered immediately
				// on next transition of this thread to the user-mode.
				//

				KeTestAlertThread(UserMode);
			}

			begin = ++i;
		}
	}



	return NT_SUCCESS(Status);
}

//////////////////////////////////////////////////////////////////////////
// Notify routines.
//////////////////////////////////////////////////////////////////////////

NTSTATUS ReadDxvkConfigFile(
	_Inout_ PBOOLEAN isDxvkConfigPresent,
	_In_ PUNICODE_STRING FilePath,
	_Inout_ PUNICODE_STRING Path,
	_Inout_ PUNICODE_STRING Dlls
)
{
	NTSTATUS status;
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;

	InjDbgPrint("ReadDxvkConfigFile: Opening file: %wZ\n", FilePath);

	InitializeObjectAttributes(&objectAttributes, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		InjDbgPrint("Failed to open file: %wZ, status: 0x%08X\n", FilePath, status);
		*isDxvkConfigPresent = FALSE;
		return status;
	}
	
	InjDbgPrint("File opened successfully: %wZ\n", FilePath);

	CHAR buffer[256];
	CHAR line[256];
	ULONG bytesRead;
	ULONG bufferOffset = 0;
	BOOLEAN endOfFile = FALSE;
	BOOLEAN foundPath = FALSE;
	BOOLEAN foundDlls = FALSE;

	while (!endOfFile)
	{
		RtlZeroMemory(buffer, sizeof(buffer));
		status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, sizeof(buffer) - 1, NULL, NULL);

		if (NT_SUCCESS(status) || status == STATUS_END_OF_FILE)
		{
			if (status == STATUS_END_OF_FILE)
			{
				endOfFile = TRUE;
			}

			buffer[ioStatusBlock.Information] = '\0'; // Null terminate the string
			bytesRead = (ULONG)ioStatusBlock.Information;

			for (ULONG i = 0; i < bytesRead; i++)
			{
				if (buffer[i] == '\n' || buffer[i] == '\r' || buffer[i] == '\0')
				{
					if (bufferOffset > 0)
					{
						line[bufferOffset] = '\0';

						if (!foundPath && strstr(line, "dxvk.dlls.FolderPath = ") == line)
						{
							CHAR* value = line + strlen("dxvk.dlls.FolderPath = ") + 1; // Skip the starting quote
							value[strlen(value) - 1] = '\0'; // Remove the ending quote
							InjDbgPrint("Raw FolderPath: %s\n", value);

							ANSI_STRING ansiString;
							UNICODE_STRING unicodeString;
							RtlInitAnsiString(&ansiString, value);

							status = RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, TRUE);
							if (NT_SUCCESS(status))
							{
								InjDbgPrint("Converted FolderPath: %wZ\n", &unicodeString);

								Path->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, unicodeString.MaximumLength, 'path');
								if (Path->Buffer)
								{
									RtlCopyMemory(Path->Buffer, unicodeString.Buffer, unicodeString.Length);
									Path->Length = unicodeString.Length;
									Path->MaximumLength = unicodeString.MaximumLength;
									InjDbgPrint("Parsed FolderPath: %wZ\n", Path);
									foundPath = TRUE;
								}
								else
								{
									InjDbgPrint("Failed to allocate memory for FolderPath\n");
									status = STATUS_INSUFFICIENT_RESOURCES;
									RtlFreeUnicodeString(&unicodeString);
									ZwClose(fileHandle);
									return status;
								}
								RtlFreeUnicodeString(&unicodeString);
							}
							else
							{
								InjDbgPrint("Failed to convert FolderPath: %s, status: 0x%08X\n", ansiString.Buffer, status);
								ZwClose(fileHandle);
								return status;
							}
						}
						else if (!foundDlls && strstr(line, "dxvk.dlls = ") == line)
						{
							CHAR* value = line + strlen("dxvk.dlls = ");
							InjDbgPrint("Raw DLLs: %s\n", value);

							ANSI_STRING ansiString;
							UNICODE_STRING unicodeString;
							RtlInitAnsiString(&ansiString, value);

							status = RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, TRUE);
							if (NT_SUCCESS(status))
							{
								InjDbgPrint("Converted DLLs: %wZ\n", &unicodeString);

								Dlls->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, unicodeString.MaximumLength, 'dlls');
								if (Dlls->Buffer)
								{
									RtlCopyMemory(Dlls->Buffer, unicodeString.Buffer, unicodeString.Length);
									Dlls->Length = unicodeString.Length;
									Dlls->MaximumLength = unicodeString.MaximumLength;
									InjDbgPrint("Parsed DLLs: %wZ\n", Dlls);
									foundDlls = TRUE;
								}
								else
								{
									InjDbgPrint("Failed to allocate memory for DLLs\n");
									status = STATUS_INSUFFICIENT_RESOURCES;
									RtlFreeUnicodeString(&unicodeString);
									ZwClose(fileHandle);
									return status;
								}
								RtlFreeUnicodeString(&unicodeString);
							}
							else
							{
								InjDbgPrint("Failed to convert DLLs: %s, status: 0x%08X\n", ansiString.Buffer, status);
								ZwClose(fileHandle);
								return status;
							}
						}

						bufferOffset = 0;

						// ≈сли обе строки найдены, выходим из внутреннего цикла
						if (foundPath && foundDlls)
						{
							break;
						}
					}
				}
				else
				{
					if (bufferOffset < sizeof(line) - 1)
					{
						line[bufferOffset++] = buffer[i];
					}
				}
			}

			// ≈сли обе строки найдены, выходим из внешнего цикла
			if (foundPath && foundDlls)
			{
				break;
			}
		}
		else
		{
			InjDbgPrint("Failed to read file: %wZ, status: 0x%08X\n", FilePath, status);
			break;
		}
	}

	ZwClose(fileHandle);
	InjDbgPrint("File closed: %wZ\n", FilePath);

	if (foundPath && foundDlls)
	{
		*isDxvkConfigPresent = TRUE;
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}

//BOOLEAN OpenDxvkConfigFileIfExists(
//	_Inout_ PHANDLE fileHandle,
//	_In_ PUNICODE_STRING FilePath
//)
//{
//	OBJECT_ATTRIBUTES objectAttributes;
//	IO_STATUS_BLOCK ioStatusBlock;
//
//	InitializeObjectAttributes(&objectAttributes, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//	// ѕытаемс€ открыть файл
//	NTSTATUS status = ZwCreateFile(fileHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
//		FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
//
//	if (NT_SUCCESS(status))
//	{
//		return TRUE;
//	}
//	else
//	{
//		return FALSE;
//	}
//}

VOID
NTAPI
InjCreateProcessNotifyRoutineEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);


	if (CreateInfo)
	{
		InjCreateInjectionInfo(NULL, ProcessId, CreateInfo->CommandLine, CreateInfo->ImageFileName);
	}
	else
	{
		InjRemoveInjectionInfoByProcessId(ProcessId, TRUE);
	}
}


VOID
NTAPI
InjLoadImageNotifyRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{

	//
	// Check if current process is injected.
	//

	PINJ_INJECTION_INFO InjectionInfo = InjFindInjectionInfo(ProcessId);

	if (!InjectionInfo || InjectionInfo->IsInjected)
	{
		return;
	}

#if defined(INJ_CONFIG_SUPPORTS_WOW64)
	//
	// If reparse-injection is enabled and this process is
	// Wow64 process, then do not track load-images.
	//

	if (InjectionInfo->Method == InjMethodWow64LogReparse &&
		PsGetProcessWow64Process(PsGetCurrentProcess()))
	{
		return;
	}
#endif

	if (PsIsProtectedProcess(PsGetCurrentProcess()))
	{
		//
		// Protected processes throw code-integrity error when
		// they are injected.  Signing policy can be changed, but
		// it requires hacking with lots of internal and Windows-
		// version-specific structures.  Simly don't inject such
		// processes.
		//
		// See Blackbone project (https://github.com/DarthTon/Blackbone)
		// if you're interested how protection can be temporarily
		// disabled on such processes.  (Look for BBSetProtection).
		//

		InjDbgPrint("[injlib]: Ignoring protected process (PID: %u, Name: '%s')\n",
			(ULONG)(ULONG_PTR)ProcessId,
			PsGetProcessImageFileName(PsGetCurrentProcess()));

		InjRemoveInjectionInfoByProcessId(ProcessId, TRUE);

		return;
	}

	if (!InjCanInject(InjectionInfo))
	{
		//
		// This process is in early stage - important DLLs (such as
		// ntdll.dll - or wow64.dll in case of Wow64 process) aren't
		// properly initialized yet.  We can't inject the DLL until
		// they are.
		//
		// Check if any of the system DLLs we're interested in is being
		// currently loaded - if so, mark that information down into the
		// LoadedDlls field.
		//

		for (ULONG Index = 0; Index < RTL_NUMBER_OF(InjpSystemDlls); Index += 1)
		{
			PUNICODE_STRING SystemDllPath = &InjpSystemDlls[Index].DllPath;

			if (RtlxSuffixUnicodeString(SystemDllPath, FullImageName, TRUE))
			{
				PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase,
					&LdrLoadDllRoutineName);

				ULONG DllFlag = InjpSystemDlls[Index].Flag;
				InjectionInfo->LoadedDlls |= DllFlag;

				switch (DllFlag)
				{
					//
					// In case of "thunk method", capture address of the LdrLoadDll
					// routine from the ntdll.dll (which is of the same architecture
					// as the process).
					//

				case INJ_SYSARM32_NTDLL_LOADED:
				case INJ_SYCHPE32_NTDLL_LOADED:
				case INJ_SYSWOW64_NTDLL_LOADED:
					if (InjectionInfo->Method != InjMethodThunkless)
					{
						InjectionInfo->LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;
					}
					break;

					//
					// For "thunkless method", capture address of the LdrLoadDll
					// routine from the native ntdll.dll.
					//

				case INJ_SYSTEM32_NTDLL_LOADED:
					InjectionInfo->LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;
					break;

				default:
					break;
				}

				//
				// Break the for-loop.
				//

				break;
			}
		}
	}
	else
	{
#if defined(INJ_CONFIG_SUPPORTS_WOW64)

		if (InjIsWindows7 &&
			InjectionInfo->Method == InjMethodThunk &&
			PsGetProcessWow64Process(PsGetCurrentProcess()))
		{
			//
			// On Windows 7, if we're injecting DLL into Wow64 process using
			// the "thunk method", we have additionaly postpone the load after
			// these system DLLs.
			//
			// This is because on Windows 7, these DLLs are loaded as part of
			// the wow64!ProcessInit routine, therefore the Wow64 subsystem
			// is not fully initialized to execute our injected Wow64ApcRoutine.
			//

			UNICODE_STRING System32Kernel32Path = RTL_CONSTANT_STRING(L"\\System32\\kernel32.dll");
			UNICODE_STRING SysWOW64Kernel32Path = RTL_CONSTANT_STRING(L"\\SysWOW64\\kernel32.dll");
			UNICODE_STRING System32User32Path = RTL_CONSTANT_STRING(L"\\System32\\user32.dll");
			UNICODE_STRING SysWOW64User32Path = RTL_CONSTANT_STRING(L"\\SysWOW64\\user32.dll");

			if (RtlxSuffixUnicodeString(&System32Kernel32Path, FullImageName, TRUE) ||
				RtlxSuffixUnicodeString(&SysWOW64Kernel32Path, FullImageName, TRUE) ||
				RtlxSuffixUnicodeString(&System32User32Path, FullImageName, TRUE) ||
				RtlxSuffixUnicodeString(&SysWOW64User32Path, FullImageName, TRUE))
			{
				InjDbgPrint("[injlib]: Postponing injection (%wZ)\n", FullImageName);
				return;
			}
		}

#endif

		//
		// All necessary DLLs are loaded - perform the injection.
		//
		// Note that injection is done via kernel-mode APC, because
		// InjInject calls ZwMapViewOfSection and MapViewOfSection
		// might be already on the callstack.  Because MapViewOfSection
		// locks the EPROCESS->AddressCreationLock, we would be risking
		// deadlock by calling InjInject directly.
		//

#if defined(INJ_CONFIG_SUPPORTS_WOW64)
		InjDbgPrint("[injlib]: Injecting (PID: %u, Wow64: %s, Name: '%s')\n",
			(ULONG)(ULONG_PTR)ProcessId,
			PsGetProcessWow64Process(PsGetCurrentProcess()) ? "TRUE" : "FALSE",
			PsGetProcessImageFileName(PsGetCurrentProcess()));
		InjDbgPrint("[injlib]: InjectionInfo->Dlls: %wZ\t InjectionInfo->Path[InjArchitectureX%d]: %wZ\n", InjectionInfo->Dlls, PsGetProcessWow64Process(PsGetCurrentProcess()) ? 86 : 64, InjectionInfo->Path[PsGetProcessWow64Process(PsGetCurrentProcess()) ? 0 : 1]);

#else
		InjDbgPrint("[injlib]: Injecting (PID: %u, Name: '%s')\n",
			(ULONG)(ULONG_PTR)ProcessId,
			PsGetProcessImageFileName(PsGetCurrentProcess()));

#endif

		InjpQueueApc(KernelMode,
			&InjpInjectApcNormalRoutine,
			InjectionInfo,
			NULL,
			NULL);

		//
		// Mark that this process is injected.
		//

		InjectionInfo->IsInjected = TRUE;
	}
}
