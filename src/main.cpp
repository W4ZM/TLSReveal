#include <Windows.h>
#include <stdio.h>
#include <cstdint>
//#include <conio.h>
#include "Mmap.hpp"
#include "utils.hpp"

#define BUFSIZE MAX_PATH
PVOID bp_address;

void injector();
void loader();
void process_debugevent(DEBUG_EVENT& de, process_info& pi);


int main()
{

    char option[3];

menu:

    do
    {
        system("cls");
        fprintf(stdout, "[>] Choose mode :\n");
        fprintf(stdout, "[1] Injector\n");
        fprintf(stdout, "[2] Loader\n");
        fprintf(stdout, "\n--> ");

        fgets(option, 3, stdin);
        size_t len = strlen(option);
        if (len && option[len-1] == '\n') option[len-1] = '\0';

    } while (strlen(option) == 0);

    int ioption = option[0] - '0';

    switch (ioption)
    {
    case 1:
        injector();
        break;

    case 2:
        loader();
        break;

    default:
        INF("invalid option !");
        goto menu; // sorry
        break;
    }

    return 0;
}



void loader()
{
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pInfo;
    process_info pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pInfo, sizeof(pInfo) );

    char name[MAX_PATH];

    do
    {
        system("cls");
        INF("Enter exe name (must be in the same folder with loader) : ");
        fprintf(stdout, "\n--> ");
        
        fgets(name, MAX_PATH, stdin);
        size_t len = strlen(name);
        if (len && name[len-1] == '\n') name[len-1] = '\0';

    } while (strlen(name) == 0);    

    system("cls");

    if (!CreateProcessA(name, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE|DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pInfo))
    {
        ERR("failed creating target process");
        getchar();
        exit(1);
    }
    
    DEBUG_EVENT de;

    pi.dwProcessId = pInfo.dwProcessId;
    pi.hProcess = pInfo.hProcess;

    // debugger loop
    while(WaitForDebugEvent(&de, INFINITE))
    {
        process_debugevent(de, pi);
    }
    
    ERR("failed to wait for debug event");
}

void process_debugevent(DEBUG_EVENT& de, process_info& pi)
{
    switch (de.dwDebugEventCode)
    {
    case LOAD_DLL_DEBUG_EVENT:
        
        {
            char Path[BUFSIZE];
            GetFinalPathNameByHandleA(de.u.LoadDll.hFile, Path, BUFSIZE, 0);
            if(!find_dll("sspicli.dll", Path)) break;
            
            // UnsealMessage()
            bp_address = reinterpret_cast<PVOID>(
                reinterpret_cast<uintptr_t>(de.u.LoadDll.lpBaseOfDll) + 0x2CD0
            );

            break_point(de, pi, bp_address, false);
            INF("break point set at : 0x%llX", (uint64_t)bp_address);
        }

        break;

    case EXCEPTION_DEBUG_EVENT:

        {   
            auto& er =  de.u.Exception.ExceptionRecord;
            if((er.ExceptionCode != EXCEPTION_BREAKPOINT) || (er.ExceptionAddress != bp_address)) break;
            INF("breakpoint hit !");

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;

            auto h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
            if (h_thread == NULL)
            {
                ERR("failed to get thread handle");
                getchar();
                exit(1);
            }

            if (GetThreadContext(h_thread, &ctx) == NULL) 
            {
                ERR("failed to get thread context");
                getchar();
                exit(1);
            }

            pi.rdx = reinterpret_cast<PVOID>(ctx.Rdx);
            //INF("closing thread handle ...");
            CloseHandle(h_thread);
            //INF("calling injector ...");
            inject_shellcode(pi, mapp_dll(pi), true);
            //INF("removing bp ...");
            break_point(de, pi, bp_address, true);
        }

        break;
    
    case EXIT_PROCESS_DEBUG_EVENT:

        INF("process terminated, press any key to exit");
        getchar();
        exit(0);

    default:
        break;
    }

    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
}

void injector()
{
    char procName[MAX_PATH];

    do
    {
        system("cls");
        INF("Enter process name: ");
        fprintf(stdout, "\n--> ");
        
        fgets(procName, MAX_PATH, stdin);
        size_t len = strlen(procName);
        if (len && procName[len-1] == '\n') procName[len-1] = '\0';

    } while (strlen(procName) == 0);

    system("cls");
    fprintf(stdout, "\n");
    INF("Process name : %s", procName);

    process_info p_info;
    if (!GetProcessIdByName(procName, p_info))
    {
        ERR("failed finding target process !");
        getchar();
        exit(1);
    }

    inject_shellcode(p_info, mapp_dll(p_info), false);
    INF("press any key to exit ...");
    getchar();
}