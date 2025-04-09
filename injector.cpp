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

BYTE* GetDllByteData(LPCWSTR lpDllFilePath) {
    // Если не верный путь к файлу или ошибка при извлечении аттрибутов
    if (GetFileAttributesW(lpDllFilePath) == INVALID_FILE_ATTRIBUTES) {
        printf("Dll file is wrong.\n");
        return NULL;
    }

    /* Поток для чтения DLL файла в бинарном формате */
    ifstream dllBinaryFile(lpDllFilePath, ios::binary | ios::ate); 

    // Если произошла ошибка при чтении файла
    if (dllBinaryFile.fail()) {
        printf("Fail when open dll file.\n");
        dllBinaryFile.close();
        return NULL;
    }

    // tellg - возвращает текущую позицию, но так как курсор стоит в конце файла (ios::ate), можно сказать, что мы получаем размер файла 
    /* Размер DLL файла */  
    streampos fileSize = dllBinaryFile.tellg();
    
    // Если файл слишком маленький (меньше 1000 байт)
    if (fileSize < 0x1000) {
        printf("Dll file is too small.\n");
        dllBinaryFile.close();
        return NULL;
    }

    /* Указатель на массив байт DLL файла */
    BYTE* pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];

    // Если произошла ошибка при инициализации массива
    if (pSrcData == NULL) {
        printf("Error when creating dll file data array\n");
        dllBinaryFile.close();
        return NULL;
    }

    // Ставит курсор на оффсет 0 от начала файла
    dllBinaryFile.seekg(0, ios::beg);
    // Записывает содержимое файла в массив pSrcData
    dllBinaryFile.read(reinterpret_cast<char*>(pSrcData), fileSize);
    // Закрывает поток
    dllBinaryFile.close();

    return pSrcData;
}
