#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <fstream>
#include <string>
#include <iostream>


std::string tm_to_readable_time(tm ctx);

using namespace KeyAuth;


std::string name = ("api_name"); 
std::string ownerid = ("api_ownerid"); 
std::string secret = ("api_secret"); 
std::string version = ("api_1.0");



api KeyAuthApp(name, ownerid, secret, version);


int runPE64(
	LPPROCESS_INFORMATION lpPI,
	LPSTARTUPINFO lpSI,
	LPVOID lpImage,
	LPWSTR wszArgs,
	SIZE_T szArgs
)
{
	#pragma region RunPE

	WCHAR wszFilePath[MAX_PATH];
	if (!GetModuleFileName(
		NULL,
		wszFilePath,
		sizeof wszFilePath
	))
	{
		return -1;
	}
	WCHAR wszArgsBuffer[MAX_PATH + 2048];
	ZeroMemory(wszArgsBuffer, sizeof wszArgsBuffer);
	SIZE_T length = wcslen(wszFilePath);
	memcpy(
		wszArgsBuffer,
		wszFilePath,
		length * sizeof(WCHAR)
	);
	wszArgsBuffer[length] = ' ';
	memcpy(
		wszArgsBuffer + length + 1,
		wszArgs,
		szArgs
	);

	PIMAGE_DOS_HEADER lpDOSHeader =
		reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
	PIMAGE_NT_HEADERS lpNTHeader =
		reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew
			);
	if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return -2;
	}

	if (!CreateProcess(
		NULL,
		wszArgsBuffer,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		lpSI,
		lpPI
	))
	{
		return -3;
	}

	CONTEXT stCtx;
	ZeroMemory(&stCtx, sizeof stCtx);
	stCtx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(lpPI->hThread, &stCtx))
	{
		TerminateProcess(
			lpPI->hProcess,
			-4
		);
		return -4;
	}

	LPVOID lpImageBase = VirtualAllocEx(
		lpPI->hProcess,
		reinterpret_cast<LPVOID>(lpNTHeader->OptionalHeader.ImageBase),
		lpNTHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (lpImageBase == NULL)
	{
		TerminateProcess(
			lpPI->hProcess,
			-5
		);
		return -5;
	}

	if (!WriteProcessMemory(
		lpPI->hProcess,
		lpImageBase,
		lpImage,
		lpNTHeader->OptionalHeader.SizeOfHeaders,
		NULL
	))
	{
		TerminateProcess(
			lpPI->hProcess,
			-6
		);
		return -6;
	}

	for (
		SIZE_T iSection = 0;
		iSection < lpNTHeader->FileHeader.NumberOfSections;
		++iSection
		)
	{
		PIMAGE_SECTION_HEADER stSectionHeader =
			reinterpret_cast<PIMAGE_SECTION_HEADER>(
				reinterpret_cast<DWORD64>(lpImage) +
				lpDOSHeader->e_lfanew +
				sizeof(IMAGE_NT_HEADERS64) +
				sizeof(IMAGE_SECTION_HEADER) * iSection
				);

		if (!WriteProcessMemory(
			lpPI->hProcess,
			reinterpret_cast<LPVOID>(
				reinterpret_cast<DWORD64>(lpImageBase) +
				stSectionHeader->VirtualAddress
				),
			reinterpret_cast<LPVOID>(
				reinterpret_cast<DWORD64>(lpImage) +
				stSectionHeader->PointerToRawData
				),
			stSectionHeader->SizeOfRawData,
			NULL
		))
		{
			TerminateProcess(
				lpPI->hProcess,
				-7
			);
			return -7;
		}
	}

	if (!WriteProcessMemory(
		lpPI->hProcess,
		reinterpret_cast<LPVOID>(
			stCtx.Rdx + sizeof(LPVOID) * 2
			),
		&lpImageBase,
		sizeof(LPVOID),
		NULL
	))
	{
		TerminateProcess(
			lpPI->hProcess,
			-8
		);
		return -8;
	}

	stCtx.Rcx = reinterpret_cast<DWORD64>(lpImageBase) +
		lpNTHeader->OptionalHeader.AddressOfEntryPoint;
	if (!SetThreadContext(
		lpPI->hThread,
		&stCtx
	))
	{
		TerminateProcess(
			lpPI->hProcess,
			-9
		);
		return -9;
	}

	if (!ResumeThread(lpPI->hThread))
	{
		TerminateProcess(
			lpPI->hProcess,
			-10
		);
		return -10;
	}

	return 0;

	#pragma endregion RunPE
}

int main()
{
	SetConsoleTitleA(XorStr("LOADER V.1.0").c_str());
	std::cout << XorStr("\n\n Connecting..");
	KeyAuthApp.init();
	system(XorStr("cls").c_str());

	std::cout << XorStr("\n[0] Login & Register (saved key) \n[1] Login & Register (new key) \n\n Choose Option : ");

	int option;
	std::string username;
	std::string password;
	std::string key;


	std::string line;
	std::ifstream myfile("C:\\Windows\\System32\\key.txt");

	std::cin >> option;
	switch (option)
	{
	case 0:

		if (myfile.is_open()) {
			while (getline(myfile, line))
			{
				KeyAuthApp.license(line);
			}
			myfile.close();
			break;
		}
		else {
			std::cout << XorStr("\n Enter license : ");
			std::cin >> key;
			std::ofstream myfile;
			myfile.open("C:\\Windows\\System32\\key.txt");
			myfile << key;
			myfile.close();
			KeyAuthApp.license(key);
			break;
		}
	case 1:
		std::cout << XorStr("\n Enter license : ");
		std::cin >> key;

		if (myfile.is_open()) {
			std::ofstream myfile;
			myfile.open("C:\\Windows\\System32\\key.txt");
			myfile << key;
			myfile.close();
		}
		else {
			std::ofstream myfile;
			myfile.open("C:\\Windows\\System32\\key.txt");
			myfile << key;
			myfile.close();
		}

		KeyAuthApp.license(key);
		break;
	default:
		std::cout << XorStr("\n\n Login failed or your license is incorrect please contact your seller !");
		Sleep(3000);
		exit(0);
	}


	if (KeyAuthApp.user_data.subscription == "YOUR_SUBSCRIPTION_NAME")
	{
		std::cout << XorStr("\n Subscription Expiry : ") << tm_to_readable_time(KeyAuthApp.user_data.expiry);
		std::cout << XorStr("\n Login Successfully wait for load !\n\n");
		Sleep(2000);

		HWND ConsWind = GetConsoleWindow();
		DWORD dwRet = 0;

		PROCESS_INFORMATION stPI;
		ZeroMemory(&stPI, sizeof stPI);
		STARTUPINFO stSI;
		ZeroMemory(&stSI, sizeof stSI);
		WCHAR szArgs[] = L"";

		std::cout << XorStr("[0] INJECTOR AND DLL \n[1] EXE CONSOLE C++  \n[2] RUN ALL EXE FILE \n\n Choose Game Support : ");

		int option;
		std::cin >> option;

		std::cout << XorStr("\n Wait a few seconds the selected software is loading correctly ...\n");

		std::ofstream file("C:\\name.dll", std::ios_base::out | std::ios_base::binary);  // FILE SAVE DLL

		switch (option)
		{

			// RUNPE
			// [0] INJECTOR AND DLL
			case 0:
			{

				std::vector<std::uint8_t> NAME_DLL = KeyAuthApp.download("990000"); //  DLL URL PANEL
				std::vector<std::uint8_t> YOUR_INJECTOR = KeyAuthApp.download("813000");  // INJECTOR URL PANEL

				system("CLS");

				file.write((char*)NAME_DLL.data(), NAME_DLL.size());
				file.close();

				if (!runPE64(&stPI, &stSI, reinterpret_cast<LPVOID>(YOUR_INJECTOR.data()), szArgs, sizeof szArgs))
				{
					WaitForSingleObject(stPI.hProcess, INFINITE);
					GetExitCodeProcess(stPI.hProcess, &dwRet);
					CloseHandle(stPI.hThread);
					CloseHandle(stPI.hProcess);
				}

				return dwRet;
			}


			// RUNPE
			// [1] EXE CONSOLE C++
		
			case 1:
			{

				std::vector<std::uint8_t> EXE_CONSOLE = KeyAuthApp.download("930000"); // CONSOLE URL PANEL

				system("CLS");

				if (!runPE64(&stPI, &stSI, reinterpret_cast<LPVOID>(EXE_CONSOLE.data()), szArgs, sizeof szArgs))
				{
					WaitForSingleObject(stPI.hProcess, INFINITE);
					GetExitCodeProcess(stPI.hProcess, &dwRet);
					CloseHandle(stPI.hThread);
					CloseHandle(stPI.hProcess);
				}

				return dwRet;
			}

			case 2:
			{
				std::vector<std::uint8_t> NORMAL_EXE = KeyAuthApp.download("516000"); // RUN NORMAL EXE

				system("CLS");

				std::ofstream file2("C:\\your_file.exe", std::ios_base::out | std::ios_base::binary);
				file2.write((char*)NORMAL_EXE.data(), NORMAL_EXE.size());
				file2.close();
				Sleep(1000);
				system("C:\\your_file.exe");
				break;
			}

			break;
		}
	}

}

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
