#include <Windows.h>
#include <tlhelp32.h>
#include "MinHook.h"
#include <stdio.h> 
#include <io.h> 
#include <stdlib.h>
#include <string.h> 


#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif


char * dumpFileToBuffer(char const* const fileName)
{
	FILE* file = fopen(fileName, "r"); /* should check the result */
	long length;
	char * buffer = 0;
	if (file)
	{
		fseek (file, 0, SEEK_END);
		length = ftell (file);
		fseek (file, 0, SEEK_SET);
		buffer = (char*)malloc (length);
		if (buffer)
		{
			fread (buffer, 1, length, file);
		}
		fclose (file);
		return buffer;
	}
	else
	{
		return NULL;
	}
}

// Helper function for MH_CreateHookApi().
template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}
typedef DWORD(WINAPI *GETFILEATTRIBUTESA)(LPCTSTR);
typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef HANDLE (WINAPI *CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); 
typedef LONG(WINAPI *REGOPENKEYEXA)(HKEY, LPCTSTR, DWORD, REGSAM, PHKEY);
typedef BOOL(WINAPI *PROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *PROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);


// Pointer for calling original MessageBoxW.
MESSAGEBOXW fpMessageBoxW = NULL;
CREATEFILEW fpCreateFileW= NULL; 
GETFILEATTRIBUTESA fpGetFileAttributesA = NULL;
REGOPENKEYEXA fpRegOpenKeyExA = NULL;
PROCESS32FIRST fpProcess32First = NULL;
PROCESS32NEXT fpProcess32Next = NULL;

//Detour function which overrides MessageBoxW.
int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}
//NTSTATUS DetourNtOpenFile (PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,ULONG ShareAccess,ULONG OpenOptions);

// Detour function which overrides CreateFileW. 
HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{ 
	char const* const fileName = "C:\\temp\\files_blackList.txt";
	char * fileBuffer = 0;
	wchar_t * pch;
	fileBuffer = dumpFileToBuffer(fileName);
	if (fileBuffer)
	{
		if(lpFileName != NULL){ 
			wprintf(L"File: %s %x %x\n",lpFileName, dwDesiredAccess, dwShareMode); 
			pch = (wchar_t *)strtok(fileBuffer, "\n");
			while (pch) {
				if(wcscmp(lpFileName,pch) == 0 && //Deny access to this one specific file 
					dwDesiredAccess == 0xC0000000){ 
						return INVALID_HANDLE_VALUE; 
				}
				pch = (wchar_t *)strtok(NULL, "\n");
			} 
			return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
		}
	} 
}
DWORD WINAPI DetourGetFileAttributesA(LPCTSTR lpFileName) 
{ 
	char const* const fileName = "C:\\temp\\files_blackList.txt";
	char * fileBuffer = 0;
	char * pch;
	fileBuffer = dumpFileToBuffer(fileName);
	if (fileBuffer)
	{
		if(lpFileName != NULL){ 
			pch = strtok(fileBuffer, "\n");
			while (pch) {
				if(strcmp((char*)lpFileName,pch) == 0)//Deny access to this one specific file )
				{ 
					return INVALID_FILE_ATTRIBUTES; 
				}
				pch = strtok(NULL, "\n");
			} 
			return fpGetFileAttributesA(lpFileName); 
		}

	}
}
LONG WINAPI DetourRegOpenKeyExA(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	if (hKey != NULL) {
		char const* const regFileName = "C:\\temp\\registry_blackList.txt";
		char * regFileBuffer = 0;
		char * pch;
		regFileBuffer = dumpFileToBuffer(regFileName);
		if (regFileBuffer) {
			pch = strtok(regFileBuffer, "\n");
			while (pch) {
				if (strcmp((char*)lpSubKey, pch) == 0)//Deny access to this one specific file )
				{
					return ERROR_KEY_DELETED;
				}
				pch = strtok(NULL, "\n");
			}
			return fpRegOpenKeyExA(hKey, lpSubKey,ulOptions,samDesired,phkResult);
		}
	}
}

BOOL WINAPI DetourProcess32First(HANDLE handleToSnapshot, LPPROCESSENTRY32 processInformation)
{
	wprintf(L"HOOKED/n");
	return fpProcess32First(handleToSnapshot, processInformation);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!fpProcess32First(handleToSnapshot, &pe32)) { //check if Process32First failed - return false
		processInformation = &pe32;
		CloseHandle(processInformation);
		return false;
	}
	WCHAR agent[MAX_PATH] = {0};
	for (size_t i = 0; i < MAX_PATH; i++)
	{
		agent[i] += pe32.szExeFile[i];
	}
	char const* const processFileName = "C:\\temp\\process_blackList.txt";
	char * processFileBuffer = 0;
	char * pch;
	processFileBuffer = dumpFileToBuffer(processFileName);
	if (processFileBuffer) {
		pch = strtok(processFileBuffer, "\n");
		while (pch) {
			if (strcmp((char*)agent, pch) == 0)//Deny access to this one specific process
			{
				return false;
				//return Process32Next(handleToSnapshot, &pe32);
				//if (!fpProcess32Next(handleToSnapshot, &pe32)) { //check if Process32First failed - return false
				//	CloseHandle(processInformation);
				//	return false;
				//}
				//continue;
			}
			pch = strtok(NULL, "\n");
		}
		processInformation = &pe32;
		return true;
	}
}

BOOL WINAPI DetourProcess32Next(HANDLE handleToSnapshot, LPPROCESSENTRY32 processInformation)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!fpProcess32Next(handleToSnapshot, &pe32)) { //check if Process32First failed - return false
		processInformation = &pe32;
		CloseHandle(processInformation);
		return false;
	}
	WCHAR agent[MAX_PATH] = { 0 };
	for (size_t i = 0; i < MAX_PATH; i++)
	{
		agent[i] += pe32.szExeFile[i];
	}
	char const* const processFileName = "C:\\temp\\process_blackList.txt";
	char * processFileBuffer = 0;
	char * pch;
	processFileBuffer = dumpFileToBuffer(processFileName);
	if (processFileBuffer) {
		pch = strtok(processFileBuffer, "\n");
		while (pch) {
			if (strcmp((char*)agent, pch) == 0)//Deny access to this one specific process
			{
				return Process32Next(handleToSnapshot, &pe32);
				//if (!fpProcess32Next(handleToSnapshot, &pe32)) { //check if Process32First failed - return false
				//	CloseHandle(processInformation);
				//	return false;
				//}
				//continue;
			}
			pch = strtok(NULL, "\n");
		}
		processInformation = &pe32;
		return true;
	}
}

BOOL APIENTRY DllMain( HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	if (DLL_PROCESS_ATTACH == ul_reason_for_call) {
		// Initialize MinHook.
		if (MH_Initialize() != MH_OK)
		{
			return FALSE;
		}
		
		// assign the hook for GetFileAttributesA.
		if (MH_CreateHookApiEx(L"Kernel32", "GetFileAttributesA", &DetourGetFileAttributesA, &fpGetFileAttributesA) != MH_OK)
		{
			return FALSE;
		}

		// Enable the hook for GetFileAttributesA.
		if (MH_EnableHook(&GetFileAttributesA) != MH_OK)
		{
			return FALSE;
		}

		// assign the hook for CreateFileW.
		if (MH_CreateHookApiEx(L"Kernel32", "CreateFileW", &DetourCreateFileW, &fpCreateFileW) != MH_OK)
		{
			return FALSE;
		}

		// Enable the hook for CreateFileW.
		//if (MH_EnableHook(&CreateFileW) != MH_OK)
		//{
		//	return FALSE;
		//}
		
		//if (MH_CreateHookApiEx(L"Kernel32", "Process32Next", &DetourProcess32Next, &fpProcess32Next) != MH_OK)
		//{
		//	return FALSE;
		//}
		//Enable the hook for MessageBoxW.
		//if (MH_EnableHook(&Process32Next) != MH_OK)
		//{
		//	return FALSE;
		//}


		//assign the hook for RegOpenKeyExA.
		if (MH_CreateHookApiEx(L"Advapi32", "RegOpenKeyExA", &DetourRegOpenKeyExA, &fpRegOpenKeyExA) != MH_OK)
		{
			return FALSE;
		}
		//Enable the hook for RegOpenKeyExA.
		if (MH_EnableHook(&RegOpenKeyExA) != MH_OK)
		{
			return FALSE;
		}
		//if (MH_CreateHookApi(L"Kernel32", "Process32First", &DetourProcess32First, reinterpret_cast<LPVOID*>(&fpProcess32First)) != MH_OK)
		//{
		//	printf("hoooked/n");
		//	return FALSE;
		//}
		//Enable the hook for MessageBoxW.
		//if (MH_EnableHook(&Process32First) != MH_OK)
		//{
		//	printf("hooked2");
		//	return FALSE;
		//}
		
	}

	return TRUE;
}