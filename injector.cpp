#include <stdio.h>
#include <string>
#include <iostream>

#include "injector.h"

using namespace std;

DWORD GetPIDByProcessName(LPCWSTR procNmae) {
    /* Дискриптор снимка всех процессов */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    /* Последняя ошибка */
    DWORD lastError = GetLastError();

    // Если снимок всех процессов завершился неудачно
    if (hSnapshot == INVALID_HANDLE_VALUE || lastError == ERROR_BAD_LENGTH) {
        return -1;
    }

    /* Сущность процесса */
    PROCESSENTRY32W entry;

    // Инициализация размера структуры (ОБЯЗАТЕЛЬНО!!!)
    entry.dwSize = sizeof(PROCESSENTRY32W);

    // Если есть хотябы один процесс
    if (Process32FirstW(hSnapshot, &entry) == TRUE) {
        // Цикл по всем процессам
        while(Process32NextW(hSnapshot, &entry) == TRUE) {
            // Если название совпадает с заданным
            if (wcscmp(entry.szExeFile, procNmae) == 0) {
                // Закрываем дескриптор
                CloseHandle(hSnapshot);
                return entry.th32ProcessID;
            }
        }
    }

    // Закрываем дескриптор
    CloseHandle(hSnapshot);

    return -1;
}
