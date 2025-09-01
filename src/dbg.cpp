#include <Windows.h>
#include <vector>
#include <cstdint>
#include "dbg.hpp"
//#include "Mmap.hpp"

#define BUFSIZE MAX_PATH

PVOID bp_address{0};
CONTEXT ctx;
HANDLE thread;
 

bool find_dll(const char* target, char* path)
{
    auto target_len = strlen(target);
    auto dll_name = (path + (strlen(path))) - target_len;
    if (stricmp(target, dll_name)) return false;
    return true;
}



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

    std::vector<char> text;
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++)
    {   
        text.resize(pBuffers[i].cbBuffer);

        if (pBuffers[i].BufferType != 0x1) continue; // != SECBUFFER_DATA

        if (!ReadProcessMemory(pi.hProcess, pBuffers[i].pvBuffer, text.data(), pBuffers[i].cbBuffer, NULL))
        {
            ERR("failed to read text buffer");
            return false;
        }

        for (ULONG j = 0; j < pBuffers[i].cbBuffer; j++) putchar(text[j]);
        printf("\n\n\n");
    }

    return true;
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
            
            // UnsealMessage() + 0x86
            bp_address = reinterpret_cast<PVOID>(
                reinterpret_cast<uintptr_t>(de.u.LoadDll.lpBaseOfDll) + 0x2D56 
            );

            if(!break_point(de, pi, bp_address, false)) return false;
            //if(!inject_shellcode(pi, map_dll(pi))) return false;
            INF("break point set at : 0x%llX", (uint64_t)bp_address);
        }

        break;

    case EXCEPTION_DEBUG_EVENT:

        {   
            auto& er =  de.u.Exception.ExceptionRecord;
            ctx.ContextFlags = CONTEXT_ALL;

            if ((er.ExceptionCode == EXCEPTION_SINGLE_STEP) && (er.ExceptionAddress == (PVOID)((uintptr_t)bp_address + 4))) // pop rdi
            {
                // set breakpoint again
                if(!break_point(de, pi, bp_address, false)) return false; 

                thread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                if (thread == NULL)
                {
                    ERR("failed to get thread handle");
                    return false;
                }

                if (GetThreadContext(thread, &ctx) == NULL) 
                {
                    ERR("failed to get thread context");
                    return false;
                }

                // clear trap flag
                ctx.EFlags &= ~0x100;
                SetThreadContext(thread, &ctx);
                CloseHandle(thread);
                break;
            }
            
            if((er.ExceptionCode != EXCEPTION_BREAKPOINT) || (er.ExceptionAddress != bp_address)) break;

            thread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
            if (thread == NULL)
            {
                ERR("failed to get thread handle");
                return false;
            }

            if (GetThreadContext(thread, &ctx) == NULL) 
            {
                ERR("failed to get thread context");
                return false;
            }

            if(!print_buffer(pi, ctx)) return false;
            if(!break_point(de, pi, bp_address, true)) return false; // remove bp
        
            // adjust RIP back and set trap flag for single-step
            ctx.Rip--;
            ctx.EFlags |= 0x100;  // Trap flag
            SetThreadContext(thread, &ctx);
            CloseHandle(thread);
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
