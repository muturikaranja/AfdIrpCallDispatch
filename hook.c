#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>

/* This was made for Windows 10.0.22000 Build 22000. Your mileage may vary */

NTSTATUS (*__fastcall original_AfdSend)(PIRP, PIO_STACK_LOCATION) = 0;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Frozen : 2;                                                    //0x6e
        USHORT HotPatch : 1;                                                  //0x6e
        USHORT Unused : 6;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    union
    {
        VOID* Spare;                                                        //0x90
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
    };
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
} _KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

__forceinline PVOID get_ntoskrnl_export(PCWSTR export_name)
{
    UNICODE_STRING export_string;
    RtlInitUnicodeString(&export_string, export_name);

    return MmGetSystemRoutineAddress(&export_string);
}

PKLDR_DATA_TABLE_ENTRY get_ldr_entry(PCWSTR base_dll_name)
{
    UNICODE_STRING base_dll_name_string;
    RtlInitUnicodeString(&base_dll_name_string, base_dll_name);

    PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)get_ntoskrnl_export(L"PsLoadedModuleList");

    /* Is PsLoadedModuleList null? */
    if (!PsLoadedModuleList)
    {
        return NULL;
    }

    /* Start iterating at LIST_ENTRY.Flink */
    PKLDR_DATA_TABLE_ENTRY iter_ldr_entry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink;

    /* If LIST_ENTRY.Flink = beginning, then it's the last entry */
    while ((PLIST_ENTRY)iter_ldr_entry != PsLoadedModuleList)
    {
        if (!RtlCompareUnicodeString(&iter_ldr_entry->BaseDllName, &base_dll_name_string, TRUE))
        {
            return iter_ldr_entry;
        }

        /* Move on to the next entry */
        iter_ldr_entry = (PKLDR_DATA_TABLE_ENTRY)iter_ldr_entry->InLoadOrderLinks.Flink;
    }

    return NULL;
}

NTSTATUS __fastcall hook_AfdSend(PIRP irp, PIO_STACK_LOCATION io_stack_location)
{
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AfdSend called:\n\t-> IRP address: %llX\n\t-> IO Stack Location address: %llX\n", irp, io_stack_location);

    /* Do whatever you want */

    return original_AfdSend(irp, io_stack_location);
}

NTSTATUS GsDriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    /* 0x4D800 is the offset for the address of AfdSend within Afd.sys */
    ULONG64* AfdSend_address = (ULONG64*)get_ldr_entry(L"Afd.sys")->DllBase + (ULONG64)0x4D800;

    /* Is Afd.sys in PsLoadedModuleList? If not then something's wrong. */
    if (AfdSend_address == 0x4D800)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Afd.sys isn't in PsLoadedModuleList?\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* Save the address of the original AfdSend. We use this function to avoid race conditions. */
    _InterlockedExchangePointer(&original_AfdSend, *AfdSend_address);

    PROCESSOR_NUMBER processor_number;
    GROUP_AFFINITY affinity, old_affinity;
    KIRQL old_irql;

    /* 
       Force the current system thread to execute on a specific logical processor (4 is a random number). 
       Turning off the Write-Protection bit only turns of write protection for a specific core. The sc-
       heduler can switch your thread to another processor anytime. Don't blindly follow the herd.
    */

    KeGetProcessorNumberFromIndex(4, &processor_number);
    RtlSecureZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
    affinity.Group = processor_number.Group;
    affinity.Mask = (KAFFINITY)1 << processor_number.Number;
    KeSetSystemGroupAffinityThread(&affinity, &old_affinity);

    /* Turn off the Write-Protection bit */
    __writecr0(__readcr0() | (1 << 16));

    /* Patch the entry containing AfdSend with our hooked AfdSend. We use this function to avoid race conditions. */
    _InterlockedExchangePointer(AfdSend_address, &hook_AfdSend);

    /* Turn on the Write-Protection bit for the specific processor, then remove the core affinity */
    __writecr0(__readcr0() & (~(1 << 16)));
    KeRevertToUserGroupAffinityThread(&old_affinity);

    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AfdSend hooked:\n\t-> Original AfdSend address: %llX\n\t-> AfdSend hook address: %llX\n", original_AfdSend, &hook_AfdSend);

    return STATUS_SUCCESS;
}
