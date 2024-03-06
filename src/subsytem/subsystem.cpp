#include "subsystem.hpp"

/**
 * Function to retrieve the subsystem of a PE image x86.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD GetSubsytem32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsystem of a PE image x64.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD GetSubsytem64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process x86.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	// ReadProcessMemory
	m_ReadProcessMemoryPtr readProcessMemory = (m_ReadProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 848101123);
	const BOOL bGetDOSHeader = readProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		// printf("[-] An error is occured when trying to get the target DOS header.\n");
		return -1;
	}

	constexpr IMAGE_NT_HEADERS32 ImageNTHeader = {};
	const BOOL bGetNTHeader = readProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);
	if (!bGetNTHeader)
	{
		// printf("[-] An error is occured when trying to get the target NT header.\n");
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process x64.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	m_ReadProcessMemoryPtr readProcessMemory = (m_ReadProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 848101123);
	const BOOL bGetDOSHeader = readProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		// printf("[-] An error is occured when trying to get the target DOS header.\n");
		return -1;
	}

	constexpr IMAGE_NT_HEADERS64 ImageNTHeader = {};
	const BOOL bGetNTHeader = readProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);
	if (!bGetNTHeader)
	{
		// printf("[-] An error is occured when trying to get the target NT header.\n");
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}