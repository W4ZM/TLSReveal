#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include "utils.hpp"
 

bool find_dll(const char* target, char* path)
{
    auto target_len = strlen(target);
    auto dll_name = (path + (strlen(path))) - target_len;
    if (stricmp(target, dll_name)) return false;
    return true;
}



void elevate_priv()
{
    TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)){
            
            auto status = AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
            switch (status)
            {
            case 0:
                INF("failed to adjust token priviliges");
                break;
            case ERROR_NOT_ALL_ASSIGNED:
                INF("The token does not have one or more of the privileges specified !!");
                break; 
            default:
                break;
            }
        }

		CloseHandle(hToken);
	}
}



bool GetProcessIdByName(char* name, process_info& pi) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
            
            //char * vOut = new char[wcslen(entry.szExeFile)+1];
            //wcstombs_s(NULL,vOut,wcslen(entry.szExeFile)+1,entry.szExeFile,wcslen(entry.szExeFile)+1);

			if (_stricmp(entry.szExeFile, name) == 0) {
				CloseHandle(snapshot);

                elevate_priv();
                INF("Process ID : %d", entry.th32ProcessID);
                auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (handle == NULL)
                {
                    ERR("failed to open target process !");
                    getchar();
                    exit(1);
                }
                
                pi.dwProcessId = entry.th32ProcessID;
                pi.hProcess = handle;
				return 1;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}



void break_point(DEBUG_EVENT& de, process_info& pi, PVOID bp_address, bool remove_bp)
{
    if(remove_bp) goto remove;
    
    static uint8_t bp = 0xCC;
    static uint8_t original_byte;

    DWORD oldProt;
    DWORD tmp;
    
    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, PAGE_EXECUTE_READWRITE, &oldProt)) 
    {
        ERR("VirtualProtectEx failed for PAGE_EXECUTE_READWRITE");
        getchar();
        exit(1);
    }

    if (!ReadProcessMemory(pi.hProcess, bp_address, &original_byte, 1, NULL))
    {
        ERR("failed reading original byte");
        getchar();
        exit(1);
    }

    if (!WriteProcessMemory(pi.hProcess, bp_address, &bp, 1, NULL))
    {
        ERR("failed setting breakpoint !");
        getchar();
        exit(1);
    }

    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, oldProt, &tmp)) 
    {
        ERR("VirtualProtectEx failed restoring old protection");
        getchar();
        exit(1);
    }

    FlushInstructionCache(pi.hProcess, bp_address, 1);

    return;

remove:

    DWORD old_Prot;
    DWORD _tmp;
    
    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, PAGE_EXECUTE_READWRITE, &old_Prot)) 
    {
        ERR("VirtualProtectEx failed for PAGE_EXECUTE_READWRITE (remove_bp)");
        getchar();
        exit(1);
    }

    if (!WriteProcessMemory(pi.hProcess, bp_address, &original_byte, 1, NULL))
    {
        ERR("failed removing breakpoint !");
        getchar();
        exit(1);
    }

    FlushInstructionCache(pi.hProcess, bp_address, 1);

    if (!VirtualProtectEx(pi.hProcess, bp_address, 1, old_Prot, &_tmp)) 
    {
        ERR("VirtualProtectEx failed restoring old protection (remove_bp)");
        getchar();
        exit(1);
    }
}
