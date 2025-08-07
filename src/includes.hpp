#pragma once
#include <Windows.h>
#include <stdio.h>

#define ERR(msg, ...) fprintf(stderr, "[-] " msg " (LastError : 0x%X)\n",  ##__VA_ARGS__, GetLastError())
#define INF(msg, ...) fprintf(stdout, "[!] " msg "\n",  ##__VA_ARGS__)

using f_LoadLibrary = HMODULE (*) (LPCSTR);
using f_GetProcAddress = FARPROC (*) (HMODULE, LPCSTR);

 struct sc_data
 {
   f_LoadLibrary __LoadLibrary;
   f_GetProcAddress __GetProcAddress;
   PVOID dll_base;
 };

DWORD WINAPI shellcode(_In_ LPVOID lpParameter);
PVOID mapp_dll(PROCESS_INFORMATION& pi);
void inject_shellcode(PROCESS_INFORMATION& pi, PVOID dll_base);
bool find_dll(const char* target, char* path);
void process_debugevent(DEBUG_EVENT& de, PROCESS_INFORMATION& pi);

