#include <Windows.h>
#include <vector>
//#include <TlHelp32.h>
#include <cstdint>
#include "utils.hpp"
 

bool find_dll(const char* target, char* path)
{
    auto target_len = strlen(target);
    auto dll_name = (path + (strlen(path))) - target_len;
    if (stricmp(target, dll_name)) return false;
    return true;
}



// void elevate_priv()
// {
//     TOKEN_PRIVILEGES priv = { 0 };
// 	HANDLE hToken = NULL;

// 	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
// 		priv.PrivilegeCount = 1;
// 		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

// 		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)){
            
//             auto status = AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
//             switch (status)
//             {
//             case 0:
//                 INF("failed to adjust token priviliges");
//                 break;
//             case ERROR_NOT_ALL_ASSIGNED:
//                 INF("The token does not have one or more of the privileges specified !!");
//                 break; 
//             default:
//                 break;
//             }
//         }

// 		CloseHandle(hToken);
// 	}
// }



// bool GetProcessIdByName(char* name) {
// 	PROCESSENTRY32 entry;
// 	entry.dwSize = sizeof(PROCESSENTRY32);

// 	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

// 	if (Process32First(snapshot, &entry) == TRUE) {
// 		while (Process32Next(snapshot, &entry) == TRUE) {

// 			if (_stricmp(entry.szExeFile, name) == 0) {
// 				CloseHandle(snapshot);

//                 //elevate_priv();
//                 INF("Process ID : %d", entry.th32ProcessID);

//                 // auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
//                 // if (handle == NULL)
//                 // {
//                 //     ERR("failed to open target process !");
//                 //     return false;
//                 // }
// 				return 1;
// 			}
// 		}
// 	}

// 	CloseHandle(snapshot);
// 	return 0;
// }



bool break_point(DEBUG_EVENT& de, PROCESS_INFORMATION& pi, PVOID bp_address, bool remove_bp)
{
    if(remove_bp) goto remove;
    
    static uint8_t bp = 0xCC;
    static uint8_t original_byte;

    DWORD oldProt;
    DWORD tmp;
    
    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, PAGE_EXECUTE_READWRITE, &oldProt)) 
    {
        ERR("VirtualProtectEx failed for PAGE_EXECUTE_READWRITE");
        return false;
    }

    if (!ReadProcessMemory(pi.hProcess, bp_address, &original_byte, 1, NULL))
    {
        ERR("failed reading original byte");
        return false;
    }

    if (!WriteProcessMemory(pi.hProcess, bp_address, &bp, 1, NULL))
    {
        ERR("failed setting breakpoint !");
        return false;
    }

    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, oldProt, &tmp)) 
    {
        ERR("VirtualProtectEx failed restoring old protection");
        return false;
    }

    FlushInstructionCache(pi.hProcess, bp_address, 1);
    return true;

remove:

    DWORD old_Prot;
    DWORD _tmp;
    
    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, PAGE_EXECUTE_READWRITE, &old_Prot)) 
    {
        ERR("VirtualProtectEx failed for PAGE_EXECUTE_READWRITE (remove_bp)");
        return false;
    }

    if (!WriteProcessMemory(pi.hProcess, bp_address, &original_byte, 1, NULL))
    {
        ERR("failed removing breakpoint !");
        return false;
    }

    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, old_Prot, &_tmp)) 
    {
        ERR("VirtualProtectEx failed restoring old protection (remove_bp)");
        return false;
    }

    FlushInstructionCache(pi.hProcess, bp_address, 1);
    return true;
}
 
bool print_buffer(PROCESS_INFORMATION& pi, CONTEXT& ctx)
{
    std::vector<uint8_t> buffer(sizeof(SecBufferDesc));

    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)ctx.Rdi, buffer.data(), sizeof(SecBufferDesc), NULL))
    {
        ERR("failed to read SecBufferDesc");
        return false;
    }

    auto MessageBuffers = reinterpret_cast<PSecBufferDesc>(buffer.data());  
    std::vector<SecBuffer> pBuffers(MessageBuffers->cBuffers);

    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)MessageBuffers->pBuffers, pBuffers.data(), sizeof(SecBuffer) * MessageBuffers->cBuffers, NULL))
    {
        ERR("failed to read SecBuffer");
        return false;
    }


    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++)
    {   
        std::vector<char> text(pBuffers[i].cbBuffer);

        if (pBuffers[i].BufferType != 0x1) continue; // != SECBUFFER_DATA

        if (!ReadProcessMemory(pi.hProcess, pBuffers[i].pvBuffer, text.data(), pBuffers[i].cbBuffer, NULL))
        {
            ERR("failed to read text buffer");
            return false;
        }

        for (ULONG j = 0; j < pBuffers[i].cbBuffer; j++) printf("%c",text[j]);
        printf("\n\n");
    }

    return true;
}
