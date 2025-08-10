#pragma once
#include <Windows.h>
#include <stdio.h>
#include "utils.hpp"


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
PVOID mapp_dll(process_info& pi); // put back PROCESS_INFORMATION
void inject_shellcode(process_info& pi, PVOID dll_base); // put back PROCESS_INFORMATION


