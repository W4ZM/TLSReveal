#include <windows.h>
#include <cstdio>


void main_function()
{
    printf("nigga im here!\n");
}


BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        
        //DisableThreadLibraryCalls(hModule);
        {
            const auto thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(main_function),
                hModule,
                0,
                nullptr
            );

            if (thread) CloseHandle(thread);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}