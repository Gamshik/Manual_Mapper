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

BOOL ManualMap(HANDLE hModule, LPCWSTR lpDllFilePath) {
#pragma region Загрузка DLL файла в бинарном формате

    /* Указатель на массив байт DLL файла */
    BYTE* pSrcData = GetDllByteData(lpDllFilePath);

    // Если произошла ошибка во время считывания данных
    if (pSrcData == NULL) {
        printf("Erorr when load binary data from DLL\n");
        return FALSE;
    }

    #pragma endregion

#pragma region Разбор DLL файла по структурам данных

    /* DOS заголовок DLL файла */
    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);

    // Если сигнатура файла не совпадает с MZ сигнатурой (стандарт)
    if (pDosHeader->e_magic != MZ_SIGNATURE) {
        printf("File signature is wrong\n");
        delete[] pSrcData;
        return FALSE;
    }

    /* PE заголовок DLL файла */            // PE заголовок расположен с оффсетом e_lfanew от начала файла
    IMAGE_NT_HEADERS* pOldNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDosHeader->e_lfanew);
    /* Optional заголовок DLL файла  
        @note Cодержит необходимую информацию для загрузки файла*/
    IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = &pOldNtHeaders->OptionalHeader;
    /* Заголовки файла
        @note Базовые характеристики файла */
    IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeaders->FileHeader;

#pragma endregion Разбор DLL файла по структурам данных

#pragma region Проверка совместимости с x64 и x86 архитектурами

#ifdef _WIN64
    if(pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Invalid platform\n");
        delete[] pSrcData;
        return FALSE;
    }
#else
    if(pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
        printf("Invalid platform\n");
        delete[] pSrcData;
        return FALSE;
    }
#endif

#pragma endregion Проверка совместимости с x64 и x86 архитектурами

#pragma region Резервирование памяти для DLL в целевом процессе

    /* Указатель на зарезервированный для DLL адрес в памяти */
    BYTE* pTargetVirtualAddr = reinterpret_cast<BYTE*>(
        VirtualAllocEx(
            hModule, 
            nullptr, 
            pOldOptionalHeader->SizeOfImage, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        )
    );

    // Если произошла ошибка при резервировании памяти
    if (pTargetVirtualAddr == NULL) {
        printf("Error when allocation memory - 0x%X\n", GetLastError());
        delete[] pSrcData;
        return FALSE;
    }

#pragma endregion Резервирование памяти для DLL в целевом процессе

#pragma region Запись всех заголовков DLL файла в зарезервированную память

    int writeHeadersResult = WriteProcessMemory(hModule, pTargetVirtualAddr, pSrcData, pOldOptionalHeader->SizeOfHeaders, NULL);

    if (writeHeadersResult == 0) {
        printf("Error when write headers to allocated memory - 0x%X\n", GetLastError());
        delete[] pSrcData;
        return FALSE;
    }

#pragma endregion Запись всех заголовков DLL файла в зарезервированную память

    MANUAL_MAPPING_DATA data{0};
    data.pLoadLibraryW = LoadLibraryW;
    data.pGetProcAddress = GetProcAddress;

    PIMAGE_SECTION_HEADER pSeactionHeader = IMAGE_FIRST_SECTION(pOldNtHeaders);

    return TRUE;
}