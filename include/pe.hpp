#ifndef OWL_PE_HPP
#define OWL_PE_HPP

#include "master.hpp"

// Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY
{
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

BOOL IsValidPE(const LPVOID lpImage);
BOOL IsPE32(const LPVOID lpImage);
BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);

#endif