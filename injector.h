#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>
#include <fstream>
#include <iostream>
#include <tlhelp32.h>

#define RELOC_FLAG32(relInfo) ((relInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(relInfo) ((relInfo >>0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
    #define RELOC_FLAG RELOC_FLAG64
#else
    #define RELOC_FLAG RELOC_FLAG32
#endif

/* Стандартная сигнатура файла PE файла */
const DWORD MZ_SIGNATURE = 0x5A4D;

using f_LoadLibraryW = HMODULE (WINAPI *)(LPCWSTR lpLibFileName);
/* Размер одной страницы в памяти */
const DWORD MEMORY_SIZE_OF_PAGE = 0x1000;

using f_GetProcAddress = FARPROC (WINAPI*)(HMODULE hMODULE, LPCSTR lpProcName);
using f_DllMain = BOOL (WINAPI*)(void* hinstDll, DWORD fDwReason, LPVOID lpvReserved);

struct MANUAL_MAPPING_DATA {
    HINSTANCE           hMod;
    f_LoadLibraryW      pLoadLibraryW;
    f_GetProcAddress    pGetProcAddress;
    BYTE*               pBaseAddr;
};

typedef MANUAL_MAPPING_DATA *PMANUAL_MAPPING_DATA;

/* Ищет PID по имени процесса.
    @param procNmae(LPCWSTR) имя процесса.

    @return Если процесс найден - PID. В ином случае - `-1`. */
DWORD GetPIDByProcessName(LPCWSTR procNmae);

/* Считывает данные из DLL в бинарном формате
    @param lpDllFilePath(LPCWSTR) путь к DLL файлу.

    @return Если успешно - `указатель на массив считанных байт`. В ином случае - `NULL`. */
PBYTE GetDllByteData(LPCWSTR lpDllFilePath);

/* Мапит DLL в указанный процесс
    @param hModule(HANDLE) дескриптор процесса, в который нужно встроить DLL.
    @param lpDllFilePath(LPCWSTR) путь к DLL файлу. 
    
    @return Если успешно - `TRUE`. В ином случае - `FALSE`.*/
BOOL ManualMap(HANDLE hModule, LPCWSTR lpDllFilePath);

/* Выполняется внутри процесса и делает все необходимые действия для запуска DLL в выполняемом прцоессе.
    @param data(PMANUAL_MAPPING_DATA) указатель на данные для маппинга в памяти
*/
void __stdcall ShellCode(PMANUAL_MAPPING_DATA data);

#endif // !INJECTOR_H