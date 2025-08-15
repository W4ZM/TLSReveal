#pragma once
#include <Windows.h>
#include <stdio.h>


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
PVOID map_dll(PROCESS_INFORMATION& pi);
bool inject_shellcode(PROCESS_INFORMATION& pi, PVOID dll_base);


