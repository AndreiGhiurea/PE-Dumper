#include "status_types.h"
#include <time.h>

DWORD FileSizeGlobal = 0;

STATUS OpenFileForDump(WIN32_FIND_DATA File, HANDLE *hIn)
{
	FileSizeGlobal = File.nFileSizeLow;

	*hIn = CreateFile(
		File.cFileName,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (INVALID_HANDLE_VALUE == *hIn || GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		return STATUS_CREATE_FILE_FAILED;
	}

	return STATUS_SUCCESS;
}

STATUS MapFileForDump(HANDLE hIn, HANDLE *hMap)
{
	DWORD FileSize, FileSizeHigh;
	FileSize = GetFileSize(hIn, &FileSizeHigh);

	*hMap = CreateFileMapping(
		hIn,
		NULL,
		PAGE_READONLY,
		FileSizeHigh,
		FileSize,
		NULL
	);

	if (NULL == *hMap)
	{
		return STATUS_MAPPING_FAILED;
	}

	return STATUS_SUCCESS;
}

STATUS MapViewForDump(HANDLE hMap, PIMAGE_DOS_HEADER *MappedFile)
{
	*MappedFile = (PIMAGE_DOS_HEADER)MapViewOfFile(
		hMap,
		FILE_MAP_READ,
		0, // FileOffsetHigh
		0, // FileOffsetLow
		0  // Map all the bytes
	);

	if (NULL == *MappedFile)
	{
		return STATUS_MAPVIEW_FAILED;
	}

	return STATUS_SUCCESS;
}

DWORD RvaToVa(PIMAGE_SECTION_HEADER SectionHeader, DWORD RVA, WORD NumberOfSections)
{	
	if (!RVA)
	{
		return 0;
	}
	else
	{
		for (WORD Section = 0; Section < NumberOfSections; Section++)
		{
			if (RVA >= SectionHeader[Section].VirtualAddress && RVA <= (SectionHeader[Section].VirtualAddress + SectionHeader[Section].SizeOfRawData))
			{
				DWORD VA = SectionHeader[Section].PointerToRawData + (RVA - SectionHeader[Section].VirtualAddress);
				if (VA >= FileSizeGlobal)
				{
					return 0;
				}
				return VA;
			}
		}
	}

	return 0;
}

STATUS PrintDumperHeader(LPSTR Filename)
{
	printf("***********Dump of file info***********\n");
	printf("* Dumping: %s\n", Filename);

	return STATUS_SUCCESS;
}

STATUS CheckDos(PIMAGE_DOS_HEADER DosHeader)
{
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("DOS Header e_magic invalid!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

STATUS CheckPe(PIMAGE_DOS_HEADER DosHeader, PIMAGE_NT_HEADERS NtHeader)
{
	if (FileSizeGlobal <= (DWORD)DosHeader->e_lfanew)
	{
		printf("No NT Header, it's probably an MS-DOS file, not a PE!\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("NT Header signature invalid!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

STATUS IsI386(PIMAGE_FILE_HEADER FileHeader)
{
	if (FileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("Not a x86 exe!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

STATUS PrintDosHeaderInfo(PIMAGE_DOS_HEADER DosHeader)
{
	printf("* DOS Header e_magic: %x (MZ)\n", DosHeader->e_magic);
	printf("* DOS Header e_lfanew: %x\n", DosHeader->e_lfanew);

	return STATUS_SUCCESS;
}

STATUS PrintNtHeaderInfo(PIMAGE_NT_HEADERS NtHeader)
{
	printf("* NT Header Signature: %x (PE)\n", NtHeader->Signature);
	printf("***************************************\n");

	return STATUS_SUCCESS;
}

STATUS PrintFileHeaderInfo(PIMAGE_FILE_HEADER FileHeader)
{
	printf("FILE HEADER\n");
	printf("   Machine: %x (Intel 386)\n", FileHeader->Machine);
	printf("   NumberOfSections: %x\n", FileHeader->NumberOfSections);
	printf("   TimeDateStamp: %x\n", FileHeader->TimeDateStamp);
	printf("   PointerToSymbolTable: %x\n", FileHeader->PointerToSymbolTable);
	printf("   NumberOfSymbols: %x\n", FileHeader->NumberOfSymbols);
	printf("   SizeOfOptionalHeader: %x\n", FileHeader->SizeOfOptionalHeader);
	printf("   Characteristics: %x\n", FileHeader->Characteristics);

	WORD Characteristics = FileHeader->Characteristics;
	if (IMAGE_FILE_DLL & Characteristics)
	{
		printf("       %s\n", "File is a DLL");
		Characteristics &= ~IMAGE_FILE_DLL;
	}
	if (IMAGE_FILE_SYSTEM & Characteristics)
	{
		printf("       %s\n", "System File");
		Characteristics &= ~IMAGE_FILE_SYSTEM;
	}
	if (IMAGE_FILE_32BIT_MACHINE & Characteristics)
	{
		printf("       %s\n", "32 bit word machine");
		Characteristics &= ~IMAGE_FILE_32BIT_MACHINE;
	}
	if (IMAGE_FILE_EXECUTABLE_IMAGE & Characteristics)
	{
		printf("       %s\n", "File is executable");
		Characteristics &= ~IMAGE_FILE_EXECUTABLE_IMAGE;
	}
	if (Characteristics)
	{
		printf("       %s\n", "+ Others");
	}
	printf("\n");

	return STATUS_SUCCESS;
}

STATUS PrintOptionalHeaderInfo(PIMAGE_OPTIONAL_HEADER OptionalHeader)
{
	printf("OPTIONAL HEADER\n");
	printf("   Magic: %x (PE32)\n", OptionalHeader->Magic);
	printf("   SizeOfCode: %x\n", OptionalHeader->SizeOfCode);
	printf("   SizeOfInitializedData: %x\n", OptionalHeader->SizeOfInitializedData);
	printf("   SizeOfUninitializedData: %x\n", OptionalHeader->SizeOfUninitializedData);
	printf("   AdressOfEntryPoint: %x\n", OptionalHeader->AddressOfEntryPoint);
	printf("   BaseOfCode: %x\n", OptionalHeader->BaseOfCode); 
	printf("   BaseOfData: %x\n", OptionalHeader->BaseOfData);
	printf("   ImageBase: %x\n", OptionalHeader->ImageBase);
	printf("   SectionAlignment: %x\n", OptionalHeader->SectionAlignment);
	printf("   FileAlignment: %x\n", OptionalHeader->FileAlignment);
	printf("   Win32Version: %x\n", OptionalHeader->Win32VersionValue);
	printf("   SizeOfImage: %x\n", OptionalHeader->SizeOfImage);
	printf("   SizeOfHeaders: %x\n", OptionalHeader->SizeOfHeaders);
	printf("   CheckSum: %x\n", OptionalHeader->CheckSum);
	printf("   Subsystem %x ", OptionalHeader->Subsystem);

	if (IMAGE_SUBSYSTEM_WINDOWS_GUI == OptionalHeader->Subsystem)
	{
		printf("(Windows GUI)\n");
	}
	else if (IMAGE_SUBSYSTEM_WINDOWS_CUI == OptionalHeader->Subsystem)
	{
		printf("(Windows CUI)\n");
	}
	else if (IMAGE_SUBSYSTEM_NATIVE == OptionalHeader->Subsystem)
	{
		printf("(Native)\n");
	}
	
	printf("   DllCharacteristics: %x\n", OptionalHeader->DllCharacteristics);
	printf("   SizeOfStackReserve: %x\n", OptionalHeader->SizeOfStackReserve);
	printf("   SizeOfStackCommit: %x\n", OptionalHeader->SizeOfStackCommit);
	printf("   SizeOfHeapReserve: %x\n", OptionalHeader->SizeOfHeapReserve);
	printf("   SizeOfHeapCommit: %x\n", OptionalHeader->SizeOfHeapCommit);
	printf("   LoaderFlags: %x\n", OptionalHeader->LoaderFlags);
	printf("   NumberOfRvaAndSizes: %x\n", OptionalHeader->NumberOfRvaAndSizes);
	
	printf("       Export Directory RVA: %x\n       Export Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	printf("       Import Directory RVA: %x\n       Import Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("       Resource Directory RVA: %x\n       Resource Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
	printf("       Exception Directory RVA: %x\n       Exception Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	printf("       Security Directory RVA: %x\n       Security Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	printf("       Relocation Directory RVA: %x\n       Relocation Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	printf("       Debug Directory RVA: %x\n       Debug Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	printf("       Architecture Directory RVA: %x\n       Architecture Directory: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
	printf("       TLS Directory RVA: %x\n       TLS Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	printf("       Configuration Directory RVA: %x\n       Configuration Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
	printf("       Bound Import Directory RVA: %x\n       Bound Import Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
	printf("       Import Address Table Directory RVA: %x\n       Import Address Table Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	printf("       Delay Import Directory RVA: %x\n       Delay Import Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
	printf("\n");

	return STATUS_SUCCESS;
}

STATUS PrintSectionHeader(WORD Section, PIMAGE_SECTION_HEADER SectionHeader, PIMAGE_DOS_HEADER DosHeader)
{
	printf("SECTION HEADER #%d\n", Section + 1);

	DWORD Remaining = FileSizeGlobal - ((PDWORD)SectionHeader - (PDWORD)DosHeader);
	if (sizeof(IMAGE_SECTION_HEADER)*Section > Remaining)
	{
		printf("   Section out of file!\n");
		return STATUS_UNSUCCESSFUL;
	}

	CHAR NameOfSection[255];
	if (strlen((char*)SectionHeader[Section].Name) > 8)
	{
		printf("   Invalid section name!\n");
	}
	else
	{
		strcpy_s(NameOfSection, strlen((char*)SectionHeader[Section].Name) + 1, (char*)SectionHeader[Section].Name);
	}

	printf("   NameOfSection: %s\n", NameOfSection);
	printf("   VirtualSize: %x\n", SectionHeader[Section].Misc.VirtualSize);
	printf("   SizeOfRawData: %x\n", SectionHeader[Section].SizeOfRawData);
	printf("   PointerToRelocations: %x\n", SectionHeader[Section].PointerToRelocations);
	printf("   PointerToLineNumbers: %x\n", SectionHeader[Section].PointerToLinenumbers);
	printf("   NumberOfRelocation: %x\n", SectionHeader[Section].NumberOfRelocations);
	printf("   NumberOfLinenumbers: %x\n", SectionHeader[Section].NumberOfLinenumbers);
	printf("   Characteristics: %x\n", SectionHeader[Section].Characteristics);

	DWORD Characteristics = SectionHeader[Section].Characteristics;
	if (IMAGE_SCN_CNT_CODE & Characteristics)
	{
		printf("   The section contains executable code.\n");
	}
	if (IMAGE_SCN_CNT_INITIALIZED_DATA & Characteristics)
	{
		printf("   The section contains initialized data.\n");
	}
	if (IMAGE_SCN_CNT_UNINITIALIZED_DATA & Characteristics)
	{
		printf("   The section contains uninitialized data.\n");
	}
	if (IMAGE_SCN_LNK_INFO & Characteristics)
	{
		printf("   The section contains comments or other information.\n");
	}
	if (IMAGE_SCN_MEM_SHARED & Characteristics)
	{
		printf("   The section can be shared in memory.\n");
	}
	if (IMAGE_SCN_MEM_EXECUTE & Characteristics)
	{
		printf("   The section can be executed as code.\n");
	}
	if (IMAGE_SCN_MEM_READ & Characteristics)
	{
		printf("   The section can be read.\n");
	}
	if (IMAGE_SCN_MEM_WRITE & Characteristics)
	{
		printf("   The section can be written to.\n");
	}

	printf("\n");

	return STATUS_SUCCESS;
}

STATUS PrintImportInfo(PIMAGE_OPTIONAL_HEADER OptionalHeader, PIMAGE_SECTION_HEADER SectionHeader, WORD NumberOfSections, PIMAGE_DOS_HEADER DosHeader)
{
	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 || !OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		printf("No imports\n\n");
		return STATUS_UNSUCCESSFUL;
	}

	DWORD ImportDescriptorRVA = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD ImportDescriptorVA = RvaToVa(SectionHeader, ImportDescriptorRVA, NumberOfSections);
	if (!ImportDescriptorVA)
	{
		return STATUS_INVALID_RVA;
	}
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)DosHeader + ImportDescriptorVA);

	printf("IMPORTS\n");

	while (ImportDescriptor->Characteristics)
	{
		DWORD NameRVA = ImportDescriptor->Name;
		DWORD NameVA = RvaToVa(SectionHeader, NameRVA, NumberOfSections);

		PDWORD Name;
		if (!NameVA)
		{
			Name = (PDWORD)"Invalid import DLL name";
		}
		else
		{
			Name = (PDWORD)(NameVA + (DWORD)DosHeader);
		}

		printf("   %s\n", (PCHAR)Name);
		printf("       Charatesritics: %x\n", ImportDescriptor->Characteristics);
		printf("       FirstThunkRVA: %x\n", ImportDescriptor->FirstThunk);
		printf("       OriginalFirstThunkRVA: %x\n", ImportDescriptor->OriginalFirstThunk);
		// Time is 0 until image is bound; printf("       Time: %x\n", ImportDescriptor->TimeDateStamp);
		// printf("       ForwarderChain: %x\n", ImportDescriptor->ForwarderChain);

		DWORD ImportLookupTableRVA;
		if (ImportDescriptor->OriginalFirstThunk)
		{
			ImportLookupTableRVA = ImportDescriptor->OriginalFirstThunk;
		}
		else
		{
			ImportLookupTableRVA = ImportDescriptor->FirstThunk;
		}
		//DWORD ImportLookupTableRVA = ImportDescriptor->OriginalFirstThunk; // ->Characteristics
		DWORD ImportLookupTableVA = RvaToVa(SectionHeader, ImportLookupTableRVA, NumberOfSections);
		if (!ImportLookupTableVA)
		{
			return STATUS_INVALID_RVA;
		}
		PIMAGE_THUNK_DATA ImportLookupTable = (PIMAGE_THUNK_DATA)(ImportLookupTableVA + (DWORD)DosHeader);

		printf("\n       Imported Functions\n");
		while (ImportLookupTable->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL(ImportLookupTable->u1.Ordinal))
			{
				printf("          Imported by ordinal: %x\n", ImportLookupTable->u1.Ordinal); // Imported by ordinal
			}
			else
			{
				DWORD ImportByNameRVA = ImportLookupTable->u1.AddressOfData;
				DWORD ImportByNameVA = RvaToVa(SectionHeader, ImportByNameRVA, NumberOfSections);
				if (!ImportByNameVA)
				{
					return STATUS_INVALID_RVA;
				}
				PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(ImportByNameVA + (DWORD)DosHeader);

				printf("          %x %s\n", ImportByName->Hint, ImportByName->Name);
			}
			ImportLookupTable++;
		}
		ImportDescriptor++;
		printf("\n");
	}

	return STATUS_SUCCESS;
}

STATUS PrintExportInfo(PIMAGE_OPTIONAL_HEADER OptionalHeader, PIMAGE_SECTION_HEADER SectionHeader, WORD NumberOfSections, PIMAGE_DOS_HEADER DosHeader)
{
	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || IMAGE_DIRECTORY_ENTRY_EXPORT >= OptionalHeader->NumberOfRvaAndSizes || !OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		printf("No exports\n\n");
		return STATUS_UNSUCCESSFUL;
	}

	DWORD ExportDirectoryRVA = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD ExportDirectoryVA = RvaToVa(SectionHeader, ExportDirectoryRVA, NumberOfSections);
	if (!ExportDirectoryVA)
	{
		return STATUS_INVALID_RVA;
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportDirectoryVA + (DWORD)DosHeader);

	DWORD NameRVA = ExportDirectory->Name;
	DWORD NameVA = RvaToVa(SectionHeader, NameRVA, NumberOfSections);
	PDWORD Name;
	if (!NameVA)
	{
		Name = (PDWORD)"Invalid Export DLL Name";
	}
	else 
	{
		Name = (PDWORD)(NameVA + (DWORD)DosHeader);
	}
	
	printf("EXPORTS\n");
	printf("   Name: %s\n", (char*)Name);
	printf("   Characteristics: %x\n", ExportDirectory->Characteristics);
	printf("   Time: %x\n", ExportDirectory->TimeDateStamp);
	printf("   Base: %x\n", ExportDirectory->Base);
	printf("   NumberOfFunctions: %x\n", ExportDirectory->NumberOfFunctions);
	printf("   NumberOfNames: %x\n", ExportDirectory->NumberOfNames);

	DWORD AdressOfFunctionsRVA = ExportDirectory->AddressOfFunctions;
	DWORD AdressOfFunctionsVA = RvaToVa(SectionHeader, AdressOfFunctionsRVA, NumberOfSections);
	if (!AdressOfFunctionsVA)
	{
		return STATUS_INVALID_RVA;
	}
	PDWORD AdressOfFunctions = (PDWORD)(AdressOfFunctionsVA + (DWORD)DosHeader);

	DWORD AdressOfNamesRVA = ExportDirectory->AddressOfNames;
	DWORD AdressOfNamesVA = RvaToVa(SectionHeader, AdressOfNamesRVA, NumberOfSections);
	if (!AdressOfNamesVA)
	{
		return STATUS_INVALID_RVA;
	}
	PDWORD AdressOfNames = (PDWORD)(AdressOfNamesVA + (DWORD)DosHeader);

	DWORD AdressOfNameOrdinalsRVA = ExportDirectory->AddressOfNameOrdinals;
	DWORD AdressOfNameOrdinalsVA = RvaToVa(SectionHeader, AdressOfNameOrdinalsRVA, NumberOfSections);
	if (!AdressOfNameOrdinalsVA)
	{
		return STATUS_INVALID_RVA;
	}
	PWORD AdressOfNameOrdinals = (PWORD)(AdressOfNameOrdinalsVA + (DWORD)DosHeader);

	printf("\n   Exported Functions By Name\n");
	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
	//	if (AdressOfFunctions[AdressOfNameOrdinals[i]] < OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
	//		|| AdressOfFunctions[AdressOfNameOrdinals[i]] > OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
	//		+ OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
	//	{
		
		// Both exported and forwarded functions
		DWORD FunNameRVA = AdressOfNames[i];
		DWORD FunNameVA = RvaToVa(SectionHeader, FunNameRVA, NumberOfSections);

		PDWORD FunName;
		if (!FunNameVA)
		{
			FunName = (PDWORD)"Unknown function name";
		}
		else
		{
			FunName = (PDWORD)(FunNameVA + (DWORD)DosHeader);
		}
		

		printf("       %s", (char*)FunName);
		printf(" %x", AdressOfNameOrdinals[i] + ExportDirectory->Base);
		DWORD FunctionRVA = AdressOfFunctions[AdressOfNameOrdinals[i]];
		printf(" %x\n", FunctionRVA);
	//	}
	}

	printf("\n   Exported Functions By Ordinal\n");
	for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		if (AdressOfFunctions[i])
		{
			DWORD j;
			for (j = 0; j < ExportDirectory->NumberOfNames; j++)
			{
				if (AdressOfFunctions[AdressOfNameOrdinals[j]] == AdressOfFunctions[i])
				{
					break; // Check if function is not exported by name, already printed
				}
			}
			if (j >= ExportDirectory->NumberOfNames)
			{
				printf("       %s", "No name");
				printf(" %x\n", i + ExportDirectory->Base);
			}
		}
	}
	
	return STATUS_SUCCESS;
}

STATUS DumpExe(WIN32_FIND_DATA File)
{
	HANDLE hIn = INVALID_HANDLE_VALUE;
	HANDLE hMap = NULL;
	PIMAGE_DOS_HEADER DosHeader = NULL;

	if (!SUCCESS(OpenFileForDump(File, &hIn)))
	{
		PRINT_ERROR("CreateFile failed");
		goto cleanup;
	}

	if (!SUCCESS(MapFileForDump(hIn, &hMap)))
	{
		PRINT_ERROR("CreateFileMapping failed");
		goto cleanup;
	}

	if (!SUCCESS(MapViewForDump(hMap, &DosHeader)))
	{
		PRINT_ERROR("MapViewOfFile failed");
		goto cleanup;
	}

	PrintDumperHeader(File.cFileName);

	if (!SUCCESS(CheckDos(DosHeader)))
	{
		goto cleanup;
	}

	PrintDosHeaderInfo(DosHeader);

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + DosHeader->e_lfanew);

	if (!SUCCESS(CheckPe(DosHeader, NtHeader)))
	{
		goto cleanup;
	}

	PrintNtHeaderInfo(NtHeader);

	PIMAGE_FILE_HEADER FileHeader = &NtHeader->FileHeader;

	if (!SUCCESS(IsI386(FileHeader)))
	{
		goto cleanup;
	}

	if (File.nFileSizeLow <= (DWORD)FileHeader->SizeOfOptionalHeader)
	{
		printf("Invalid optional header!\n");
		goto cleanup;
	}

	PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)OptionalHeader + FileHeader->SizeOfOptionalHeader);

	PrintFileHeaderInfo(FileHeader);
	PrintOptionalHeaderInfo(OptionalHeader);

	for (WORD Section = 0; Section < FileHeader->NumberOfSections; Section++)
	{
		PrintSectionHeader(Section, SectionHeader, DosHeader);
	}

	PrintImportInfo(OptionalHeader, SectionHeader, FileHeader->NumberOfSections, DosHeader);
	PrintExportInfo(OptionalHeader, SectionHeader, FileHeader->NumberOfSections, DosHeader);
	
cleanup:
	if (hIn != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hIn); // Close file handle
	}
	if (hMap != NULL)
	{
		CloseHandle(hMap); // Close mapping handle
	}
	if (DosHeader != NULL)
	{
		UnmapViewOfFile(DosHeader); // Unmap view of file
	}

	return STATUS_SUCCESS;
}