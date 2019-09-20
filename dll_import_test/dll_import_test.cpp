// dll_import_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>


int main()
{
	HINSTANCE hinstLib;
	GetKeyStorageInterfaceFn ProcGetKeyStorageInterface;
	BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

	// Get a handle to the DLL module.

	hinstLib = LoadLibrary(TEXT("diamondhsm-cng-ksp.dll"));

	// If the handle is valid, try to get the function address.

	if (hinstLib != NULL)
	{
		ProcGetKeyStorageInterface = (GetKeyStorageInterfaceFn)GetProcAddress(hinstLib, "GetKeyStorageInterface");

		// If the function address is valid, call the function.

		if (NULL != ProcGetKeyStorageInterface)
		{
			int result = (ProcGetKeyStorageInterface)(TEXT(""), NULL, 0L);
			std::cout << "result == " << result << std::endl;
			std::cin.ignore();
		}
		else
		{
			std::cout << "Function not found" << std::endl;
			std::cin.ignore();
		}
		// Free the DLL module.

		fFreeResult = FreeLibrary(hinstLib);
	}
	else
	{
		std::cout << "DLL not found" << std::endl;
		std::cin.ignore();
	}

	return 0;
}

