#pragma once
#include <stdio.h>

#define ERR(msg, ...) fprintf(stderr, "[-] " msg " (LastError : 0x%X)\n",  ##__VA_ARGS__, GetLastError())
#define INF(msg, ...) fprintf(stdout, "[!] " msg "\n",  ##__VA_ARGS__)


typedef struct _SecBuffer {
  unsigned long cbBuffer;
  unsigned long BufferType;
  void* pvBuffer;
} SecBuffer, *PSecBuffer;


typedef struct _SecBufferDesc {
  unsigned long ulVersion;
  unsigned long cBuffers;
  PSecBuffer    pBuffers;
} SecBufferDesc, *PSecBufferDesc;
 

bool find_dll(const char* target, char* path);
//bool GetProcessIdByName(char* name, process_info& pi);
// void elevate_priv();
bool break_point(DEBUG_EVENT& de, PROCESS_INFORMATION& pi, PVOID bp_address, bool remove_bp);
bool print_buffer(PROCESS_INFORMATION& pi, CONTEXT& ctx);