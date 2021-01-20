#include <stdio.h>
#include <windows.h>
#include <iostream>

LPVOID lpJmpRealloc = nullptr;
DWORD Backup_Eax, Handle, Address_1, New, Old, * DwSizee;
ULONG AllocationType, Protect;

const DWORD_PTR __declspec(naked) GetGateAddress()
{
	__asm
	{
		mov eax, dword ptr fs : [0xC0]
		ret
	}
}


void __declspec(naked) hk_NtAllocateVirtualMemory()
{
	__asm {
		mov Backup_Eax, eax
		mov eax, [esp + 0x8]
		mov Handle, eax
		mov eax, [esp + 0xC]
		mov Address_1, eax
		mov eax, [esp + 0x14]
		mov DwSizee, eax
		mov eax, [esp + 0x18]
		mov AllocationType, eax
		mov eax, [esp + 0x1C]
		mov Protect, eax
		mov eax, Backup_Eax
		pushad
	}

	printf("NtAVM Handle: [%x] Address: [0x%x]  Size: [%d]  AllocationType: [%d]  Protect: [0x%x]\n", Handle, Address_1, *DwSizee, AllocationType, Protect);

	__asm popad
	__asm jmp lpJmpRealloc
}


void __declspec(naked) hk_NtProtectVirtualMemory()
{
	__asm {
		mov Backup_Eax, eax
		mov eax, [esp + 0x8]
		mov Handle, eax
		mov eax, [esp + 0xC]
		mov Address_1, eax
		mov eax, [esp + 0x10]
		mov DwSizee, eax
		mov eax, [esp + 0x14]
		mov New, eax
		mov eax, [esp + 0x18]
		mov Old, eax
		mov eax, Backup_Eax
		pushad
	}

	printf("NtPVM Handle: [%x] Address: [0x%x]  Size: [%d]  NewProtect: [0x%x]\n", Handle, Address_1, *DwSizee, New);

	__asm popad
	__asm jmp lpJmpRealloc
}


void __declspec(naked) hk_NtReadVirtualMemory()
{
	__asm pushad

	printf("Calling NtReadVirtualMemory.\n");

	__asm popad
	__asm jmp lpJmpRealloc
}


void __declspec(naked) hk_Wow64Trampoline()
{
	__asm
	{
		cmp eax, 0x3f //64bit Syscall id of NtReadVirtualMemory
		je hk_NtReadVirtualMemory
		cmp eax, 0x50 //64bit Syscall id of NtProtectVirtualMemory
		je hk_NtProtectVirtualMemory
		cmp eax, 0x18 //64bit Syscall id of NtAllocateVirtualMemory
		je hk_NtAllocateVirtualMemory
		jmp lpJmpRealloc
	}
}

const LPVOID CreateNewJump()
{
	DWORD_PTR Gate = GetGateAddress();
	lpJmpRealloc = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	memcpy(lpJmpRealloc, (void*)Gate, 9);

	return lpJmpRealloc;
}

const void WriteJump(const DWORD_PTR dwWow64Address, const void* pBuffer, size_t ulSize)
{
	DWORD dwOldProtect = 0;
	VirtualProtect((LPVOID)dwWow64Address, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	(void)memcpy((void*)dwWow64Address, pBuffer, ulSize);
	VirtualProtect((LPVOID)dwWow64Address, 0x1000, dwOldProtect, &dwOldProtect);
}


const void EnableWow64Redirect()
{
	LPVOID Hook_Gate = &hk_Wow64Trampoline;

	char trampolineBytes[] =
	{
		0x68, 0xDD, 0xCC, 0xBB, 0xAA,       /*push 0xAABBCCDD*/
		0xC3,                               /*ret*/
		0xCC, 0xCC, 0xCC                    /*padding*/
	};
	memcpy(&trampolineBytes[1], &Hook_Gate, 4);
	WriteJump(GetGateAddress(), trampolineBytes, sizeof(trampolineBytes));
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole();// ·ÖÅä console
		FILE* fp;
		freopen_s(&fp, "CONOUT$", "w", stdout); //cmd
		printf("Gate: %p\n", GetGateAddress());
		printf("Trampoline Gate: %p\n", CreateNewJump());
		printf("Hook Gate: %p\n", hk_Wow64Trampoline);
		EnableWow64Redirect();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}