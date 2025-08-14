#include <windows.h>
#include <cstdio>

typedef struct _SecBuffer {
  unsigned long cbBuffer;
  unsigned long BufferType;
  void  *pvBuffer;
} SecBuffer, *PSecBuffer;


typedef struct _SecBufferDesc {
  unsigned long ulVersion;
  unsigned long cBuffers;
  PSecBuffer    pBuffers;
} SecBufferDesc, *PSecBufferDesc;

DWORD WINAPI main_function(_In_ LPVOID lpParameter)
{
    printf("rdx has 0x%llX", (UINT64)lpParameter);

    auto MessageBuffers = reinterpret_cast<PSecBufferDesc>(lpParameter);
    auto pBuffers = reinterpret_cast<PSecBuffer>(MessageBuffers->pBuffers);

    auto buffer = reinterpret_cast<char*>(pBuffers->pvBuffer);
    auto size = pBuffers->cbBuffer;

    while (true)
    {
        
        for (size_t i = 0; i < size; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) { // Printable ASCII range
            printf("%c", buffer[i]);
        } else {
            printf("."); // Non-printable chars as dots
        }
        }
        printf("\n");
        
        Sleep(10);
    }

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