#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include "Mmap.hpp"
#include "utils.hpp"

#define BUFSIZE MAX_PATH

 
// void process_debugevent(DEBUG_EVENT& de, PROCESS_INFORMATION& pi)
// {
//     switch (de.dwDebugEventCode)
//     {
//     case LOAD_DLL_DEBUG_EVENT:
        
//         {
//             char Path[BUFSIZE];
//             GetFinalPathNameByHandleA(de.u.LoadDll.hFile, Path, BUFSIZE, 0);
//             if(!find_dll("sspicli.dll", Path)) break;
//             inject_shellcode(pi, mapp_dll(pi));
//         }

//         break;
    
//     default:
//         break;
//     }

//     ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
// }

extern process_info pi;

int main()
{
    // STARTUPINFOA si={sizeof(si)};
    // PROCESS_INFORMATION pi;

    // ZeroMemory( &si, sizeof(si) );
    // si.cb = sizeof(si);
    // ZeroMemory( &pi, sizeof(pi) );

    // if (!CreateProcessA("crackme.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE|DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
    // {
    //     ERR("failed creating target process");
    //     getchar();
    //     exit(1);
    // }
    
    // DEBUG_EVENT de;

    // // debugger loop
    // while(WaitForDebugEvent(&de, INFINITE))
    // {
    //     process_debugevent(de, pi);
    // }
    
    // ERR("failed to wait for debug event");
    // return 1;

    char procName[MAX_PATH];

    INF("Enter process name: ");

    do
    {
        fgets(procName, MAX_PATH, stdin);
        size_t len = strlen(procName);
        if (len && procName[len-1] == '\n') procName[len-1] = '\0';

    } while (strlen(procName) == 0);
    
    fprintf(stdout, "\n");
    INF("Process name : %s", procName);

    if (!GetProcessIdByName(procName))
    {
        ERR("failed finding target process !");
        getchar();
        exit(1);
    }

    inject_shellcode(pi, mapp_dll(pi));
    getchar();
    return 0;
}
