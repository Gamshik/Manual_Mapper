// #include <string>
#include <windows.h>
#include <Lmcons.h>
#include <iostream>

#include "injector.h"

using namespace std;

const wchar_t* dllPath = L"D:\\ProgrammingAndProjects\\C++\\Manual_Mapper\\dll\\simple.dll";
const wchar_t* procName = L"Taskmgr.exe";

int main() {
    DWORD pid = GetPIDByProcessName(procName);

    if (pid == -1) { 
        printf("Pid don`t found\n");
        return -1;
    } else {
        printf("Pid id %d\n", pid);
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process: %u\n", GetLastError());
        return 1;
    }

    if (ManualMap(hProcess, dllPath)) {
        printf("Manual mapping succeeded\n");
    } else {
        printf("Manual mapping failed\n");
    }

    CloseHandle(hProcess);
    
    cin.get();
    return 0;
}
