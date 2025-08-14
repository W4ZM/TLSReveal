#include <Windows.h>
#include <stdio.h>
#include <cstdint>
//#include <conio.h>
//#include "Mmap.hpp"
#include "utils.hpp"

#define BUFSIZE MAX_PATH
#define EXE_NAME "crackme.exe"
PVOID bp_address{0};

//void injector();
bool start_debugger(DEBUG_EVENT& de, PROCESS_INFORMATION& pi);
bool process_debug_event(DEBUG_EVENT& de, PROCESS_INFORMATION& pi);



int main()
{
    do
    {
        STARTUPINFOA si={sizeof(si)};
        PROCESS_INFORMATION pi;
        DEBUG_EVENT de;
        
        ZeroMemory( &si, sizeof(si) );
        si.cb = sizeof(si);
        ZeroMemory( &pi, sizeof(pi) );

        if (!CreateProcessA(EXE_NAME, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE|DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
        {
            ERR("failed creating target process");
            break;
        }
        
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



bool process_debug_event(DEBUG_EVENT& de, PROCESS_INFORMATION& pi)
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
                reinterpret_cast<uintptr_t>(de.u.LoadDll.lpBaseOfDll) + 0x2D56 // add rsp, 58
            );

            if(!break_point(de, pi, bp_address, false)) return false;
            INF("break point set at : 0x%llX", (uint64_t)bp_address);
        }

        break;

    case EXCEPTION_DEBUG_EVENT:

        {   
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            HANDLE h_thread;

            auto& er =  de.u.Exception.ExceptionRecord;

            if ((er.ExceptionCode == EXCEPTION_SINGLE_STEP) && (er.ExceptionAddress == (PVOID)((uintptr_t)bp_address + 4))) // pop Rdi
            {
                if(!break_point(de, pi, bp_address, false)) return false; // set breakpoint again

                h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                if (h_thread == NULL)
                {
                    ERR("failed to get thread handle");
                    return false;
                }

                if (GetThreadContext(h_thread, &ctx) == NULL) 
                {
                    ERR("failed to get thread context");
                    return false;
                }

                ctx.EFlags &= ~0x100; // clear trap flag
                SetThreadContext(h_thread, &ctx);
                CloseHandle(h_thread);
                break;
            }
            
            if((er.ExceptionCode != EXCEPTION_BREAKPOINT) || (er.ExceptionAddress != bp_address)) break;
            //INF("breakpoint hit !");

            h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
            if (h_thread == NULL)
            {
                ERR("failed to get thread handle");
                return false;
            }

            if (GetThreadContext(h_thread, &ctx) == NULL) 
            {
                ERR("failed to get thread context");
                return false;
            }

            if(!print_buffer(pi, ctx)) return false;
            if(!break_point(de, pi, bp_address, true)) return false; // remove bp
            //inject_shellcode(pi, mapp_dll(pi), true);
            // adjust RIP back and set trap flag for single-step
            ctx.Rip--;
            ctx.EFlags |= 0x100;  // Trap flag
            SetThreadContext(h_thread, &ctx);
            CloseHandle(h_thread);
        }

        break;
     
    case EXIT_PROCESS_DEBUG_EVENT:

        INF("process terminated !\n");
        return false;

    default:
        break;
    }

    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    return true;
}

// void inject(PROCESS_INFORMATION& pi)
// {
    
//     INF("Process to inject : %s", EXE_NAME);

//     if (!GetProcessIdByName(EXE_NAME, pi))
//     {
//         ERR("failed finding target process !");
//         getchar();
//         exit(1);
//     }

//     inject_shellcode(p_info, mapp_dll(p_info), false);
//     INF("press any key to exit ...");
//     getchar();
// }