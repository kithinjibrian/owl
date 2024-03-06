#ifndef OWL_LOADER_HPP
#define OWL_LOADER_HPP

#include "master.hpp"

#pragma comment(lib, "wininet.lib")

HANDLE GetFileContent(const LPSTR lpFilePath);
LPVOID GetDownloadFileContent(const char *url);

#endif