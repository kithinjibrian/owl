#include "reloc.hpp"

/**
 * Function to check if the source image has a relocation table x86.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL HasRelocation32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/**
 * Function to check if the source image has a relocation table x64.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL HasRelocation64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/**
 * Function to retrieve the IMAGE_DATA_DIRECTORY reloc of a x86 image.
 * \param lpImage : PE source image.
 * \return : 0 if fail else the data directory.
 */
IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return {0, 0};
}

/**
 * Function to retrieve the IMAGE_DATA_DIRECTORY reloc of a x64 image.
 * \param lpImage : PE source image.
 * \return : 0 if fail else the data directory.
 */
IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return {0, 0};
}