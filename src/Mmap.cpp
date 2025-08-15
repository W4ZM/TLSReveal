#include <Windows.h>
#include <thread>
#include "Mmap.hpp"
#include "dbg.hpp"
#include "dll.hpp"

 
HANDLE h_thread; // remote thread handle


DWORD WINAPI shellcode(LPVOID lp)
{
    auto scd = reinterpret_cast<sc_data*>(lp);
    auto image_base = reinterpret_cast<uint8_t*>(scd->dll_base);
    auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(
        image_base + reinterpret_cast<PIMAGE_DOS_HEADER>(image_base)->e_lfanew);
    auto& imp_dir_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto import_table = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image_base + imp_dir_entry.VirtualAddress);
    
    // resolve relocations
    if ((nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == NULL) return 0x1111;
    
    auto& reloc_dir_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(reloc_dir_entry.VirtualAddress == NULL) return 0x2222;

    auto relocation_table = reinterpret_cast<PIMAGE_BASE_RELOCATION>(image_base + reloc_dir_entry.VirtualAddress);
    uintptr_t delta = reinterpret_cast<uintptr_t>(image_base) - nt_header->OptionalHeader.ImageBase;
    
    while (relocation_table->VirtualAddress != NULL)
    {
        size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        auto relocation_data = reinterpret_cast<uint16_t*>(&relocation_table[1]);

        for (size_t i = 0; i < relocations; i++)
        {
            auto relocation = relocation_data[i];
            uint16_t type = relocation >> 12;
            uint16_t offset = relocation & 0xFFF;
            
            auto ptr = reinterpret_cast<uintptr_t*>(image_base + relocation_table->VirtualAddress + offset);
            if(type == IMAGE_REL_BASED_DIR64) *ptr += delta;
        }
        
        relocation_table = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<uint8_t*>(relocation_table) + relocation_table->SizeOfBlock
        );
    }

    //resolve imports
    while (import_table->OriginalFirstThunk != NULL)
    {
        auto dll_name = reinterpret_cast<char*>(image_base + import_table->Name);
        auto dll_import = scd->__LoadLibrary(dll_name);
        if (dll_import == NULL) return 0x3333;
        
        auto lookup_table = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + import_table->OriginalFirstThunk);
        auto address_table = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + import_table->FirstThunk);

        while (lookup_table->u1.AddressOfData != NULL)
        {
            FARPROC func;
            auto lookup_address = lookup_table->u1.AddressOfData;
            
            if ((lookup_address & IMAGE_ORDINAL_FLAG64) != NULL)
            {
                func = scd->__GetProcAddress(dll_import, reinterpret_cast<LPCSTR>(lookup_address & 0xFFFFFFFF));
                if(func == NULL) return 0x4444;
            }
            else
            {
                auto import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + lookup_address);
                func = scd->__GetProcAddress(dll_import, import_name->Name);
                if(func == NULL) return 0x5555;
            }
            
            address_table->u1.Function = reinterpret_cast<uint64_t>(func);
            ++lookup_table;
            ++address_table;
        }
        ++import_table;
    }
    
    // resolve tls callbacks
    if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != NULL)
    {
        auto tls_dir_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        auto* tls_table = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(image_base + tls_dir_entry.VirtualAddress);
        auto* tls_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls_table->AddressOfCallBacks);

        while (tls_callback != NULL) 
        {
            (*tls_callback)(image_base, DLL_PROCESS_ATTACH, NULL);
            tls_callback++;
        }
    } 
    
    // register exception tables
    auto& excep_dir_entry  = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (excep_dir_entry.Size && excep_dir_entry.VirtualAddress) 
    {
        auto pFuncTable = reinterpret_cast<PRUNTIME_FUNCTION>(image_base + excep_dir_entry.VirtualAddress);
        ULONG entryCount = excep_dir_entry.Size / sizeof(RUNTIME_FUNCTION);
        
        if (scd->__RtlAddFunctionTable(pFuncTable, entryCount, reinterpret_cast<DWORD64>(image_base)) == FALSE) return 0x6666;
    }
    
    // call DllMain
    using f_DllMain = BOOL (__stdcall*) (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    auto __DllMain = reinterpret_cast<f_DllMain>(image_base + nt_header->OptionalHeader.AddressOfEntryPoint);    
    return __DllMain(reinterpret_cast<HINSTANCE>(image_base), DLL_PROCESS_ATTACH, NULL);
}



PVOID map_dll(PROCESS_INFORMATION& pi) 
{
    auto dll_base = reinterpret_cast<uint8_t*>(dll_data);
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERR("image has no valid DOS header !");
        return NULL;
    }

    auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_base + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        ERR("image has no valid NT header !");
        return NULL;
    }

    if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        ERR("only 64-bit dll's are supported !");
        return NULL;
    }
    
    auto dll_address = VirtualAllocEx(pi.hProcess,
        NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!dll_address)
    {
        ERR("failed allocating memory for dll !");
        return NULL;
    }

    // copy the headers to the allocated dll
    auto status = WriteProcessMemory(pi.hProcess, dll_address, dll_base, nt_header->OptionalHeader.SizeOfHeaders, NULL);
    if (!status)
    {
        ERR("failed copyig headers to the allocated dll");
        return NULL;
    }

    // copy the sections to the allocated dll
    auto section_table = reinterpret_cast<PIMAGE_SECTION_HEADER>(
    reinterpret_cast<uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
    for (uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
    {
        if (section_table[i].SizeOfRawData > 0)
        {
            auto status = WriteProcessMemory(pi.hProcess,
                reinterpret_cast<uint8_t*>(dll_address) + section_table[i].VirtualAddress, // in memory
                dll_base + section_table[i].PointerToRawData, // in disk
                section_table[i].SizeOfRawData , NULL);
            if (!status)
            {
                ERR("failed copyig sections to the allocated memory");
                return NULL;
            }
        }
    }
    
    INF("dll mapped at 0x%llX", (uint64_t)dll_address);
    return dll_address;
}



bool inject_shellcode(PROCESS_INFORMATION& pi, PVOID dll_base) 
{
    if(dll_base == NULL) return false;
    
    // allocate a page
    auto sc_address = VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_address)
    {
        ERR("failed allocating memory for shellcode");
        return false;
    }

    auto status = WriteProcessMemory(pi.hProcess, sc_address, shellcode, 0x1000, NULL);
    if (!status)
    {
        ERR("failed writing shellcode to target process");
        return false;
    }

    HMODULE hmod;
    if (!(hmod = GetModuleHandleA("kernel32.dll")))
    {
        ERR("failed getting kernel32 handle");
        return false;
    }

    FARPROC fn;
    sc_data sd;
    if (!(fn = GetProcAddress(hmod, "GetProcAddress")))
    {
        ERR("failed getting address of GetProcAddress");
        return false;
    }
    sd.__GetProcAddress = reinterpret_cast<f_GetProcAddress>(reinterpret_cast<PVOID>(fn));
    
    if (!(fn = GetProcAddress(hmod, "LoadLibraryA")))
    {
        ERR("failed getting address of LoadLibraryA");
        return false;
    }
    sd.__LoadLibrary = reinterpret_cast<f_LoadLibrary>(reinterpret_cast<PVOID>(fn));

    if (!(fn = GetProcAddress(hmod, "RtlAddFunctionTable")))
    {
        ERR("failed getting address of RtlAddFunctionTable");
        return false;
    }
    sd.__RtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(reinterpret_cast<PVOID>(fn));

    sd.dll_base = dll_base;
    auto sd_addr = VirtualAllocEx(pi.hProcess, NULL, sizeof(sd), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sd_addr)
    {
        ERR("failed allocating memory for shell code data");
        return false;
    }

    status = WriteProcessMemory(pi.hProcess, sd_addr, &sd, sizeof(sd), NULL);
    if (!status)
    {
        ERR("failed writing shell code data to target process");
        return false;
    }
    
    h_thread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)sc_address, sd_addr, 0, NULL);
    if (!h_thread)
    {
        ERR("failed creating remote thread");
        return false;
    }
    
    Sleep(1000);
    std::thread wait_for([]{
        
        DWORD exitCode = 0;
        INF("waiting for remote thread ...");
        
        auto waitResult = WaitForSingleObject(h_thread, INFINITE);
        if (waitResult != WAIT_OBJECT_0)
        {
            ERR("failed waiting for remote thread !");
            CloseHandle(h_thread);
            return;
        }

        GetExitCodeThread(h_thread, &exitCode);
        switch (exitCode)
        {
        case 0x1111:
            INF("dll cant be relocated !");
            break;
        
        case 0x2222:
            INF("dll can be relocated but contains no relocation directory !");
            break;

        case 0x3333:
            INF("LoadLibrary failure");
            break;

        case 0x4444:
            INF("GetProcAddress failure (by ordinal)");
            break;

        case 0x5555:
            INF("GetProcAddress failure (by name)");
            break;
        
        default:
            INF("thread exited with %X", exitCode);
            break;
        }
 
        CloseHandle(h_thread);
        return;
    });

    wait_for.detach();
    return true;
}
