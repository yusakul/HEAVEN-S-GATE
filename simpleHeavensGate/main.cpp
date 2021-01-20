#include <stdio.h>
#include <Windows.h>
#include "wow64ext.h"
#include <cstddef>
#include "internal.h"
#include "CMemPtr.h"

DWORD getCurrentThreadId(){
	__asm{
		mov eax, FS:[0x24];
	}
}

DWORD64 ErrorFunc(){
	DWORD back_esp = 0;
	WORD back_fs = 0;
	__asm{
		mov    back_fs, fs;
        mov    back_esp, esp;
		and    esp, 0xFFFFFFF0;
		CPUP_RETURN_FROM_SIMULATED_CODE();
	}
	MessageBoxA(NULL, "test", "test_cap", MB_OK);
	__asm{
		RUN_SIMULATED_CODE();
        mov    ax, ds;
        mov    ss, ax;
        mov    esp, back_esp;
        mov    ax, back_fs;
        mov    fs, ax;
	}

	return 0;
}

int main(){
	STARTUPINFO si = {0,};
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);

	DWORD tid = getCurrentThreadId();
	printf("Tid: %d\n", tid);
	DWORD64 tid2 = GetCurrentThreadId64();
	printf("Tid64: %d\n", tid2);

	/*
	HANDLE chProc = NULL;
	HANDLE hParent = GetCurrentProcess();
	DWORD64 res = CreateProcessEx64(
		&chProc,
        PROCESS_ALL_ACCESS,
        NULL,
        hParent,
        4,
        NULL,
        NULL,
        NULL,
        FALSE);
	*/

	if(CreateProcess(L"C:\\Windows\\system32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)){
			DWORD pid = pi.dwProcessId;
			HANDLE hProc = pi.hProcess;
			bool printMemMap = true;
			static const size_t TEST_SIZE = 0x1000; // 1 Page Size
			DWORD64 mem = VirtualAllocEx64(hProc, NULL, TEST_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (0 == mem)
			{
				printf("VirtualAllocEx64 failed.\n");
				return -1;
			}
			printf("Memory allocated at: %016I64X\n", mem);

			MEMORY_BASIC_INFORMATION64 mbi64 = { 0 };
			VirtualQueryEx64(hProc, mem, &mbi64, sizeof(mbi64));
			printf("Changing protection from PAGE_READWRITE to PAGE_EXECUTE_READWRITE...\n");
			DWORD oldProtect = 0;
			VirtualProtectEx64(hProc, mem, mbi64.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
			VirtualQueryEx64(hProc, mem, &mbi64, sizeof(mbi64));

			BYTE testBuf[TEST_SIZE];
			for (int i = 0; i < TEST_SIZE; i++)
				testBuf[i] = 'a';
    
			SIZE_T wrSz = 0;
			if (!WriteProcessMemory64(hProc, mem, testBuf, TEST_SIZE, &wrSz) || (wrSz != TEST_SIZE))
			{
				printf("FAILED on WriteProcessMemory64\n");
				return -1;
			}
			DebugBreak();
			printf("TerminateProcess: %d\n", pi.dwProcessId);
			TerminateProcess(pi.hProcess, 0);
	}
	return 0;
}