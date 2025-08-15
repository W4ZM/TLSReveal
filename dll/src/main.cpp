#include <windows.h>
#include <cstdio>

 
DWORD WINAPI main_function(_In_ LPVOID lpParameter)
{
    puts("hello world !");
    return 0;
}


BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        {
            const auto thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(main_function),
                lpReserved,
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