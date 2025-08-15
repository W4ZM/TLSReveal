#include <Windows.h>
#include <stdio.h>
#include <cstdint>
//#include "Mmap.hpp"
#include "dbg.hpp"

#define EXE_NAME "crackme.exe"

bool start_debugger(DEBUG_EVENT& de, PROCESS_INFORMATION& pi);

int main()
{
    do
    {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory( &si, sizeof(si) );
        si.cb = sizeof(si);
        ZeroMemory( &pi, sizeof(pi) );

        DEBUG_EVENT de;

        if (!CreateProcessA(EXE_NAME, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE|DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
        {
            ERR("failed creating target process");
            break;
        }

        //if(!inject_shellcode(pi, map_dll(pi))) break;
        if (!start_debugger(de, pi)) break;

    } while (false);

    system("pause");
    return 1;
}



bool start_debugger(DEBUG_EVENT& de, PROCESS_INFORMATION& pi)
{
    // debugger loop
    while(WaitForDebugEvent(&de, INFINITE))
    {
        if (!process_debug_event(de, pi))
            return false;
    }

    ERR("failed to wait for debug event");
    return false;
}