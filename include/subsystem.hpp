#ifndef OWL_SUBSYSTEM_HPP
#define OWL_SUBSYSTEM_HPP

#include "master.hpp"

DWORD GetSubsytem32(const LPVOID lpImage);
DWORD GetSubsytem64(const LPVOID lpImage);
DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress);
DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress);

#endif