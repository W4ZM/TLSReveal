#include <Windows.h>
#include <stdio.h>
#include <string>
#include "dll.hpp"
#include "includes.hpp"

#define BUFSIZE MAX_PATH



DWORD WINAPI shellcode(LPVOID lp)
{
    auto scd = reinterpret_cast<sc_data*>(lp);
    
    return 0;
}



PVOID mapp_dll(PROCESS_INFORMATION& pi)
{
    auto dll_base = reinterpret_cast<uint8_t*>(dll_data);
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERR("image has no valid DOS header !");
        getchar();
        exit(1);
    }

    auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_base + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        ERR("image has no valid NT header !");
        getchar();
        exit(1);
    }

    if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        ERR("only 64-bit dll's are supported !");
        getchar();
        exit(1);
    }
    
    auto dll_address = VirtualAllocEx(pi.hProcess,
         NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!dll_address)
    {
        ERR("failed allocating memory for dll !");
        getchar();
        exit(1);
    }

    // copy the headers to the allocated dll
    auto status = WriteProcessMemory(pi.hProcess, dll_address, dll_base, nt_header->OptionalHeader.SizeOfHeaders, NULL);
    if (!status)
    {
        ERR("failed copyig headers to the allocated dll");
        getchar();
        exit(1);
    }

    // copy the sections to the allocated dll
    auto section_table = reinterpret_cast<PIMAGE_SECTION_HEADER>(
    reinterpret_cast<uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
    for (uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
    {
        if (section_table[i].SizeOfRawData > 0)
        {
            auto status = WriteProcessMemory(pi.hProcess,
                reinterpret_cast<uint8_t*>(dll_address) + section_table[i].VirtualAddress,
                dll_base, section_table[i].SizeOfRawData , NULL);
            if (!status)
            {
                ERR("failed copyig sections to the allocated dll");
                getchar();
                exit(1);
            }
        }
    }
    
    INF("dll mapped successfully !");
    return dll_address;
}



void inject_shellcode(PROCESS_INFORMATION& pi, PVOID dll_base) 
{
    auto sc_address = VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_address)
    {
        ERR("failed allocating memory for shellcode");
        getchar();
        exit(1);
    }

    auto status = WriteProcessMemory(pi.hProcess, sc_address, shellcode, 0x1000, NULL);
    if (!status)
    {
        ERR("failed writing shellcode to target process");
        getchar();
        exit(1);
    }

    HMODULE hmod;
    if (!(hmod = GetModuleHandleA("kernel32.dll")))
    {
        ERR("failed getting module handle");
        getchar();
        exit(1);
    }

    FARPROC fn;
    sc_data sd;
    if (!(fn = GetProcAddress(hmod, "GetProcAddress")))
    {
        ERR("failed getting address of GetProcAddress");
        getchar();
        exit(1);
    }
    sd.__GetProcAddress = reinterpret_cast<f_GetProcAddress>(reinterpret_cast<PVOID>(fn));
    
    if (!(fn = GetProcAddress(hmod, "LoadLibraryA")))
    {
        ERR("failed getting address of LoadLibraryA");
        getchar();
        exit(1);
    }
    sd.__LoadLibrary = reinterpret_cast<f_LoadLibrary>(reinterpret_cast<PVOID>(fn));

    sd.dll_base = dll_base;
    auto sd_addr = VirtualAllocEx(pi.hProcess, NULL, sizeof(sd), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sd_addr)
    {
        ERR("failed allocating memory for shell code data");
        getchar();
        exit(1);
    }

    status = WriteProcessMemory(pi.hProcess, sd_addr, &sd, sizeof(sd), NULL);
    if (!status)
    {
        ERR("failed writing shell code data to target process");
        getchar();
        exit(1);
    }

    auto h_thread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)sc_address, sd_addr, 0, NULL);
    if (!h_thread)
    {
        ERR("failed creating remote thread");
        getchar();
        exit(1);
    }
    
    CloseHandle(h_thread);
    INF("shellcode injected !");
}



bool find_dll(const char* target, char* path)
{
    auto target_len = strlen(target);
    auto dll_name = (path + (strlen(path))) - target_len;
    if (stricmp(target, dll_name)) return false;
    return true;
}



void process_debugevent(DEBUG_EVENT& de, PROCESS_INFORMATION& pi)
{
    switch (de.dwDebugEventCode)
    {
    case LOAD_DLL_DEBUG_EVENT:
        
        {
            char Path[BUFSIZE];
            GetFinalPathNameByHandleA(de.u.LoadDll.hFile, Path, BUFSIZE, 0);
            if(!find_dll("sspicli.dll", Path)) break;
            inject_shellcode(pi, mapp_dll(pi));
        }

        break;
    
    default:
        break;
    }

    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
}