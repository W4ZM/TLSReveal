#pragma once
#include <Windows.h>
#include <stdio.h>

#define ERR(msg, ...) fprintf(stderr, "[-] " msg " (LastError : 0x%X)\n",  ##__VA_ARGS__, GetLastError())
#define INF(msg, ...) fprintf(stdout, "[!] " msg "\n",  ##__VA_ARGS__)

using f_LoadLibrary = HMODULE (*) (LPCSTR);
using f_GetProcAddress = FARPROC (*) (HMODULE, LPCSTR);
using f_RtlAddFunctionTable = NTSYSAPI BOOLEAN (*) (PRUNTIME_FUNCTION, DWORD, DWORD64);


struct sc_data
{
  f_LoadLibrary __LoadLibrary;
  f_GetProcAddress __GetProcAddress;
  f_RtlAddFunctionTable __RtlAddFunctionTable; 
  PVOID dll_base;
};

DWORD WINAPI shellcode(_In_ LPVOID lpParameter);
PVOID mapp_dll(PROCESS_INFORMATION& pi);
void inject_shellcode(PROCESS_INFORMATION& pi, PVOID dll_base);


