#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>
#include <fstream>
#include <iostream>
#include <tlhelp32.h>

/* Стандартная сигнатура файла PE файла */
const DWORD MZ_SIGNATURE = 0x5A4D;

using f_LoadLibraryW = HMODULE (WINAPI *)(LPCWSTR lpLibFileName);
using f_GetProcAddress = FARPROC (WINAPI*)(HMODULE hMODULE, LPCSTR lpProcName);
using f_DllMain = BOOL (WINAPI*)(HINSTANCE hinstDll, DWORD fDwReason, LPVOID lpvReserved);

struct MANUAL_MAPPING_DATA {
    HINSTANCE           hMod;
    f_LoadLibraryW      pLoadLibraryW;
    f_GetProcAddress    pGetProcAddress;
};

/* Ищет PID по имени процесса.
    @param procNmae(LPCWSTR) имя процесса.

    @return Если процесс найден - PID. В ином случае - `-1`. */
DWORD GetPIDByProcessName(LPCWSTR procNmae);

/* Считывает данные из DLL в бинарном формате
    @param lpDllFilePath(LPCWSTR) путь к DLL файлу.

    @return Если успешно - `указатель на массив считанных байт`. В ином случае - `NULL`. */
BYTE* GetDllByteData(LPCWSTR lpDllFilePath);

/* Мапит DLL в указанный процесс
    @param hModule(HANDLE) дескриптор процесса, в который нужно встроить DLL.
    @param lpDllFilePath(LPCWSTR) путь к DLL файлу. 
    
    @return Если успешно - `TRUE`. В ином случае - `FALSE`.*/
BOOL ManualMap(HANDLE hModule, LPCWSTR lpDllFilePath);

#endif // !INJECTOR_H