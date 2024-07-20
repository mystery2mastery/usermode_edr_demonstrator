#include <Windows.h>
#include <iostream>

BOOL InjectDLLWithEarlyBirdAPC(const char* targetProcessPath, const char* dllPath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Create the target process in a suspended state
    if (!CreateProcessA(NULL, (LPSTR)targetProcessPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcessA failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(pi.hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "GetModuleHandleA failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        std::cerr << "GetProcAddress failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Queue an APC to the main thread of the target process
    if (!QueueUserAPC((PAPCFUNC)pLoadLibraryA, pi.hThread, (ULONG_PTR)pRemoteBuf)) {
        std::cerr << "QueueUserAPC failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    //getchar();
    // Resume the main thread of the target process
    if (ResumeThread(pi.hThread) == -1) {
        std::cerr << "ResumeThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Clean up handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

int main() {
    const char* targetProcessPath = "\\path\\to\\your\\process.exe"; //"C:\\Windows\\System32\\notepad.exe"
    const char* dllPath = "path\\to\\HookingEngine.dll";

    if (InjectDLLWithEarlyBirdAPC(targetProcessPath, dllPath)) {
        std::cout << "DLL injection succeeded." << std::endl;
    }
    else {
        std::cout << "DLL injection failed." << std::endl;
    }

    return 0;
}
