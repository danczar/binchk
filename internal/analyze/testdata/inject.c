/* Inert test sample: imports the classic process-injection APIs but only
   calls them on an impossible branch. Used to test import heuristics. */
#include <windows.h>
int main(int argc, char **argv) {
    if (argc > 1000) {
        HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)argc);
        LPVOID m = VirtualAllocEx(p, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(p, m, argv, 16, NULL);
        CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL);
        SetWindowsHookExA(WH_KEYBOARD_LL, NULL, NULL, 0);
        GetAsyncKeyState(0);
    }
    return 0;
}
