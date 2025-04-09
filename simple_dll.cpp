#include <windows.h>
#include <winuser.h>

VOID ShowMessageBox(LPCWSTR lpMessage) {
    MessageBoxW(NULL, lpMessage, L"Gamshikk", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(  
    HINSTANCE hinstDll, 
    DWORD fDwReason, 
    LPVOID lpvReserved
) {
    switch (fDwReason) {
        case DLL_PROCESS_ATTACH:
            ShowMessageBox(L"Dll process is attached!");
            break;  
        case DLL_PROCESS_DETACH:
            ShowMessageBox(L"Dll process is deteached!");
            break;
        case DLL_THREAD_ATTACH:
            ShowMessageBox(L"Dll thread is attached!");
            break;
        case DLL_THREAD_DETACH:
            ShowMessageBox(L"Dll thread is deteached!");
            break;
    }
    return TRUE;
}
