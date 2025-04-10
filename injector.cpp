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

PBYTE GetDllByteData(LPCWSTR lpDllFilePath) {
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
    PBYTE pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];

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
    PBYTE pSrcData = GetDllByteData(lpDllFilePath);

    // Если произошла ошибка во время считывания данных
    if (pSrcData == NULL) {
        printf("Erorr when load binary data from DLL\n");
        return FALSE;
    }

#pragma endregion Загрузка DLL файла в бинарном формате

#pragma region Разбор DLL файла по структурам данных

    /* DOS заголовок DLL файла */
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData);

    // Если сигнатура файла не совпадает с MZ сигнатурой (стандарт)
    if (pDosHeader->e_magic != MZ_SIGNATURE) {
        printf("File signature is wrong\n");
        delete[] pSrcData;
        return FALSE;
    }

    /* PE заголовок DLL файла */            // PE заголовок расположен с оффсетом e_lfanew от начала файла
    PIMAGE_NT_HEADERS pOldNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + pDosHeader->e_lfanew);
    /* Optional заголовок DLL файла  
        @note Cодержит необходимую информацию для загрузки файла*/
    PIMAGE_OPTIONAL_HEADER pOldOptionalHeader = &pOldNtHeaders->OptionalHeader;
    /* Заголовки файла
        @note Базовые характеристики файла */
    PIMAGE_FILE_HEADER pOldFileHeader = &pOldNtHeaders->FileHeader;

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
    PBYTE pBaseAddr = reinterpret_cast<PBYTE>(
        VirtualAllocEx(
            hModule, 
            reinterpret_cast<LPVOID>(pOldOptionalHeader->ImageBase), 
            pOldOptionalHeader->SizeOfImage, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        )
    );

    // Если произошла ошибка при резервировании памяти
    if (pBaseAddr == NULL) {
        printf("Error when allocation memory - 0x%X\n", GetLastError());
        delete[] pSrcData;
        return FALSE;
    }

#pragma endregion Резервирование памяти для DLL в целевом процессе

#pragma region Инициализациия MANUAL_MAPPING_DATA структуры

    // Инициализация вспомогательной структуры
    /* Вспомогательная структура с данными */
    MANUAL_MAPPING_DATA data{0};
    // Присвоение ссылки на оригинальную функцию LoadLibraryW
    data.pLoadLibraryA = LoadLibraryA;
    // Присвоение ссылки на оригинальную функцию GetProcAddress
    data.pGetProcAddress = GetProcAddress;
    // Присвоение ссылки на зарезервированную память
    data.pBaseAddr = pBaseAddr;

#pragma endregion Инициализациия MANUAL_MAPPING_DATA структуры

#pragma region Запись всех заголовков DLL файла в зарезервированную память
    /* Результат записи всех заголовков в зарезервированную память */
    BOOL writeHeadersResult = WriteProcessMemory(hModule, pBaseAddr, pSrcData, pOldOptionalHeader->SizeOfHeaders, NULL);

    // Если произошла ошибка во время записи заголовков
    if (writeHeadersResult == 0) {
        printf("Error when write headers to allocated memory - 0x%X\n", GetLastError());       
        delete[] pSrcData;
        VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
        return FALSE;
    }

#pragma endregion Запись всех заголовков DLL файла в зарезервированную память

#pragma region Запись всех секций DLL файла в зарезервированную память

    /* Указатель на массив секций DLL файла */
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeaders);

    for (int i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData == 0) continue;

        /* Результат записи секции в зарезервированную память */
        BOOL resultWriteSection = WriteProcessMemory(
            hModule,
            pBaseAddr + pSectionHeader->VirtualAddress,
            pSrcData + pSectionHeader->PointerToRawData,
            pSectionHeader->SizeOfRawData,
            NULL
        );

        // Если произошла ошибка во время записи секции
        if (resultWriteSection == 0) {
            printf("Error when write section to allocated memory - 0x%X\n", GetLastError());
            VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
            delete[] pSrcData;
            delete[] pSectionHeader;
            return FALSE;
        }
    }
    
#pragma endregion Запись всех секций DLL файла в зарезервированную память

#pragma region Резервирование памяти для MANUAL_MAPPING_DATA структуры

    /* Указатель на выделеннюу для структуры MANUAL_MAPPING_DATA память */
    PBYTE pDataAddr = reinterpret_cast<PBYTE>(
        VirtualAllocEx(
            hModule, 
            nullptr, 
            sizeof(data), 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        )
    );

    /* Если при выделении памяти возникла ошибка */
    if (pDataAddr == NULL) {
        printf("Error when allocated memory for data - 0x%X\n", GetLastError());
        VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
        delete[] pSrcData;
        delete[] pSectionHeader;
        return FALSE;
    }
    
#pragma endregion Резервирование памяти для MANUAL_MAPPING_DATA структуры

#pragma region Запись MANUAL_MAPPING_DATA в память

    /* Результат записи MANUAL_MAPPING_DATA  в память */
    BOOL dataWriteMemoryResult = WriteProcessMemory(hModule, pDataAddr, &data, sizeof(data), NULL);

    // Если возникла ошибка при записи в память
    if (dataWriteMemoryResult == 0) {
        printf("Error when write data to memory - 0x%X\n", GetLastError());
        VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hModule, pDataAddr, 0, MEM_RELEASE);
        return FALSE;
    }

#pragma endregion Запись MANUAL_MAPPING_DATA в память

    // Очистка памяти, так как больше не пригодится, все данные записаны в зарезервированную память
    delete[] pSrcData;

#pragma region Резервирование памяти для функции ShellCode

    /* Указатель на адрес выделенной памяти для функции ShellCode */
    PBYTE pShellCodeAddr = reinterpret_cast<PBYTE>(
        VirtualAllocEx(
            hModule,
            nullptr,
            MEMORY_SIZE_OF_PAGE, // 0x1000 - 4096byte - размер одной страницы 
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    );

    // Если возникла ошибка при выделении памяти
    if (pShellCodeAddr == NULL) {
        printf("Error when allocate memory for shell code - 0x%X\n", GetLastError());
        VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hModule, pDataAddr, 0, MEM_RELEASE);
        return FALSE;
    }

#pragma endregion Резервирование памяти для функции ShellCode

#pragma region Запись ShellCode в память

    /* Результат записи функции ShellCode в память */
    BOOL shellCodeWriteMemoryResult = 
        WriteProcessMemory(
            hModule,
            pShellCodeAddr,
            reinterpret_cast<LPCVOID>(ShellCode),
            MEMORY_SIZE_OF_PAGE,
            NULL
        ); 

    // Если возникла ошибка при записи в память
    if (shellCodeWriteMemoryResult == 0) {
        printf("Error when write shellcode to memory - 0x%X\n", GetLastError());
        VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hModule, pDataAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hModule, pShellCodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

#pragma endregion Запись ShellCode в память

#pragma region Вызов ShellCode 

    /* Дескриптор потока */
    HANDLE hThread = CreateRemoteThread(
        hModule, 
        nullptr, 
        0, 
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCodeAddr),
        pDataAddr,
        0,
        NULL
    );

    // Если произошла ошибка при создании потока
    if (hThread == NULL) {
        printf("Error when create thread for shell code - 0x%X", GetLastError());
        VirtualFreeEx(hModule, pShellCodeAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hModule, pDataAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // Закрытие дескриптора потока
    CloseHandle(hThread);

#pragma endregion Вызов ShellCode 

#pragma region Ожидание успешного завершения ShellCode

    /* Переменная для проверки успешности вызова ShellCode */
    HINSTANCE hCheck = NULL;

    // Пока hCheck не будет присвоено значение
    while (hCheck == NULL) {
        /* Структура данных для проверки */
        MANUAL_MAPPING_DATA dataChecker { 0 };

        // Cчитывание структуры данных
        ReadProcessMemory(hModule, pDataAddr, &dataChecker, sizeof(MANUAL_MAPPING_DATA), NULL);
        
        // Присвоение значения hMod 
        // (в конце функции ShellCode данному полю присваивается значение отличное от NULL)
        hCheck = dataChecker.hMod;
        
        Sleep(1000);
    }

#pragma endregion Ожидание успешного завершения ShellCode

    // Очистка памяти
    VirtualFreeEx(hModule, pShellCodeAddr, 0, MEM_RELEASE);
    VirtualFreeEx(hModule, pBaseAddr, 0, MEM_RELEASE);
    VirtualFreeEx(hModule, pDataAddr, 0, MEM_RELEASE);

    return TRUE;
}


void __stdcall ShellCode(PMANUAL_MAPPING_DATA data) {
    if (!data)
        return;

#pragma region Инициализация переменных 

    /* Указатель на адрес загруженной DLL */
    PBYTE pBaseAddr = data->pBaseAddr;

    /* DOS заголовок DLL файла */
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr); 
    /* PE заголовок DLL файла */ 
    PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pBaseAddr + pDosHeader->e_lfanew);
    /* Optional заголовок DLL файла  
        @note Cодержит необходимую информацию для загрузки файла. */
    PIMAGE_OPTIONAL_HEADER pOptHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pNtHeader->OptionalHeader); 

    /* Указатель на оригинальную функцию pLoadLibraryA */
    auto _loadLibraryA = data->pLoadLibraryA;
    /* Указатель на оригинальную функцию pGetProcAddress */
    auto _getProcAddress = data->pGetProcAddress;

    /* Указатель на функцию входа DLL - `DllMain` */
    auto _dllEntryPoint = reinterpret_cast<f_DllMain>(pBaseAddr + pOptHeader->AddressOfEntryPoint);

#pragma endregion Инициализация переменных

#pragma region Релокация адресов в памяти

   /* Смещение после внедрения DLL */
   PBYTE locationDelta = pBaseAddr - pOptHeader->ImageBase;
    
   // Если смещение присутствует
   if (locationDelta) {
       // Если размер таблицы со смещениями равен 0
       if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
           return;

       /* Оффсет до таблицы смещений */
       DWORD relocTableOffset = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

       /* Указатель на массив таблиц смещений */
       PIMAGE_BASE_RELOCATION pRelocTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBaseAddr + relocTableOffset);
       
       // Перебор всех блоков
       while (pRelocTable->VirtualAddress) {
           /* Количество сущностей в таблице смещений */  // SizeOfBlock - размер всего блока, IMAGE_BASE_RELOCATION - заголовок блока, WORD - размер каждой сущности в блоке
           UINT amountOfEntries = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
           /* Указатель на массив с информацией о релокации сущностей в блоке 
               @note Состоит из двух частей первая - `[ 4bit: type  ]`, вторая - `[ 12bit: offset ]`. */
           PWORD pRelativeInfo = reinterpret_cast<WORD*>(pRelocTable + 1);

           // Перебор сущностей в блоке
           for (UINT i = 0; i != amountOfEntries; ++i, ++pRelativeInfo) {
               if (RELOC_FLAG(*pRelativeInfo)) {
                   /* Указатель на адрес текущей сущности */                                               // Выдялем из информации только оффсет, занулив первые 4 бита (тип); 0x0FFF - 0000 1111 1111 1111
                   PUINT_PTR pSrcAddr = reinterpret_cast<PUINT_PTR>(pBaseAddr + pRelocTable->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                   // Смещаем сущность на оффсет
                   *pSrcAddr += reinterpret_cast<UINT_PTR>(locationDelta);
               }
           }

           // Смещаем на один блок
           pRelocTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(pRelocTable) + pRelocTable->SizeOfBlock);
       }
   }

#pragma endregion Релокация адресов в памяти

#pragma region Исправление импортов

    // Если таблица с импортами корректна
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        /* Оффсет до таблицы импортов */
        DWORD importTableOffset = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

        /* Указатель на массив таблиц импортов для каждой DLL  */
        PIMAGE_IMPORT_DESCRIPTOR pImportTable = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBaseAddr + importTableOffset);

        // Перебор всех таблиц импортов для каждой DLL
        while (pImportTable->Name) {
            /* Имя импортируемой DLL */
            char* importedDllName = reinterpret_cast<char*>(pBaseAddr + pImportTable->Name);
            
            /* Дескриптор DLL */
            HMODULE hDll = _loadLibraryA(importedDllName);

            /* Указатель на начало таблицы ILT */
            PULONG_PTR pThunkRef = reinterpret_cast<PULONG_PTR>(pBaseAddr + pImportTable->OriginalFirstThunk);
            /* Указатель на начало таблицы IAT */
            PULONG_PTR pFuncRef = reinterpret_cast<PULONG_PTR>(pBaseAddr + pImportTable->FirstThunk);

            // Если импорты уже решены, нужно удостовериться, что будут перебираться все существующие импорты
            // Иногда импорты могут быть уже решены: статическая линковка или до этого обработалось,
            // в таком случае всё равно нужно перебрать все импорты, чтобы присвоить актуальные адреса,
            // только нужно по-другому обрабатывать, что предусмотрено в цикле
            if (!pThunkRef)
                pThunkRef = pFuncRef;
                
            // Перебор всех импортов
            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                // Если импорт представляет собой адрес (сущность из IAT)
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    // Обновляется адресс на импорт 
                    *pFuncRef = (ULONG_PTR)_getProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                    
                // Если импорт представляет собой имя (сущность из ILT)
                } else {
                    // Указатель на структуру с именем функции
                    PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBaseAddr + (*pThunkRef));
                    // Обновляется адресс на импорт 
                    *pFuncRef = (ULONG_PTR)_getProcAddress(hDll, pImportByName->Name);
                }
            }
            ++pImportTable;
        }
    }

#pragma endregion Исправление импортов

#pragma region Вызов TLS callback функций

    // Если данные с TLS корректны
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        /* Оффсет до TLS директории */
        DWORD tlsDirectoryOffset = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

        /* Указатель на TLS директорию */
        PIMAGE_TLS_DIRECTORY pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBaseAddr + tlsDirectoryOffset);

        /* Указатель на массив с TLS колбэками */
        PIMAGE_TLS_CALLBACK* pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

        // (*pCallBack)(pBaseAddr, DLL_PROCESS_ATTACH, nullptr);
        
        // Вызов всех TLS колбэков
        while (pCallBack && *pCallBack) {
            (*pCallBack)(pBaseAddr, DLL_PROCESS_ATTACH, nullptr);
            ++pCallBack;
        }
    }

#pragma endregion Вызов TLS callback функций

#pragma region Вызов DllMain

    _dllEntryPoint(pBaseAddr, DLL_PROCESS_ATTACH, nullptr);

#pragma endregion Вызов DllMain

    // Присвоение указателя на DLL, чтобы по завершению работы метода проверить успешность завершения
    data->hMod = reinterpret_cast<HINSTANCE>(*pBaseAddr);
}
