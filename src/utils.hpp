#pragma once
#include <stdio.h>

#define ERR(msg, ...) fprintf(stderr, "[-] " msg " (LastError : 0x%X)\n",  ##__VA_ARGS__, GetLastError())
#define INF(msg, ...) fprintf(stdout, "[!] " msg "\n",  ##__VA_ARGS__)
 


struct process_info
{
    HANDLE hProcess;
    DWORD dwProcessId;
    PVOID rdx;
};


bool find_dll(const char* target, char* path);
bool GetProcessIdByName(char* name, process_info& pi);
void elevate_priv();
void break_point(DEBUG_EVENT& de, process_info& pi, PVOID bp_address, bool remove_bp);