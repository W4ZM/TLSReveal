#include <Windows.h>
#include <stdio.h>
#include "includes.hpp"



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
