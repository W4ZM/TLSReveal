#include <Windows.h>
#include <stdio.h>
#include "Mmap.hpp"

#define BUFSIZE MAX_PATH

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


int main()
{
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    if (!CreateProcessA("crackme.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE|DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
    {
        ERR("failed creating target process");
        getchar();
        exit(1);
    }
    
    DEBUG_EVENT de;

    // debugger loop
    while(WaitForDebugEvent(&de, INFINITE))
    {
        process_debugevent(de, pi);
    }
    
    ERR("failed to wait for debug event");
    return 1;
}
