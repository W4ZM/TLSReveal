# TLSReveal

Automatically Launch and debug an executable, specifically targeting the `UnsealMessage` function in `sspicli.dll` to monitor TLS protocol buffer data recieved from a server, and includes a manual DLL mapper to inject custom Dll into the target process.

---

## Features

* **Process Debugging**: Launches and attaches to any 64-bit executable under the control of the Windows Debug API.
* **Targeted Memory Inspection**: Sets a breakpoint on `sspicli!UnsealMessage` and automatically parses the `SecBufferDesc` and `SecBuffer` structures to extract and display the `pvBuffer` data upon execution.
* **Manual DLL Mapping**: by manually mapping a 64-bit DLL into the target process's address space, bypassing standard `LoadLibrary` calls.
* **Cmake Script**: Includes a `.cmake` script to automatically build and generate hex bytes from the dll and include them via header file in the project before it builds. 


## Getting Started

Follow these instructions to build and run the project .

### Building from Source

1.  **Clone the repository**
    `git clone https://github.com/W4ZM/TLSReveal.git`

2.  **Build**
    ```bash
    cd TLSReveal\
    
    mkdir build\ && cd build\

    cmake ..
    cmake --build . --config Release
    ```

### Usage

Change the `#define EXE_NAME "target.exe"` in `src\main.cpp` to the name of target executable.
Launch The `Loader.exe` in the same folder with the target exe.  
[video](https://youtu.be/hYsclEIyoYg)  

---
