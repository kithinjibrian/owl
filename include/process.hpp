#ifndef OWL_PROCESS_HPP
#define OWL_PROCESS_HPP

#include "master.hpp"

// Structure to store the address process infromation.
struct ProcessAddressInformation
{
	LPVOID lpProcessPEBAddress;
	LPVOID lpProcessImageBaseAddress;
};

void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent);
void CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent);
ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI);
ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI);

#endif