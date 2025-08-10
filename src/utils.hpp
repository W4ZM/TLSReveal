#pragma once
#include <stdio.h>

#define ERR(msg, ...) fprintf(stderr, "[-] " msg " (LastError : 0x%X)\n",  ##__VA_ARGS__, GetLastError())
#define INF(msg, ...) fprintf(stdout, "[!] " msg "\n",  ##__VA_ARGS__)
 


struct process_info
{
    HANDLE hProcess;
    DWORD dwProcessId;
};


bool find_dll(const char* target, char* path);
DWORD GetProcessIdByName(char* name);
void elevate_priv();