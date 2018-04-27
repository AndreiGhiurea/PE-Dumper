#include "status_types.h"
#include "list.h"

STATUS DumpExe(LPSTR SrcPath, DWORD FileSize, LPSTR DestPath);

DWORD NrFilesProcessed = 0;

DWORD WINAPI ListScanThreadFunction(
	_In_ LPVOID lpParameter)
{
	UNREFERENCED_PARAMETER(lpParameter);

	DWORD EventResult;
	PLIST_ENTRY ListEntryDump = NULL;
	PLIST_ITEM ListItemDump = NULL;
	PLIST_ITEM_PARAM ListItemParam = NULL;
	HANDLE  EventList[3];
	EventList[0] = NewItemEvent;
	EventList[2] = NoMoreFilesEvent;
	EventList[1] = EndEvent;

	while (TRUE)
	{
		EventResult = WaitForMultipleObjects(3, EventList, FALSE, INFINITE);
		if (WAIT_FAILED == EventResult)
		{
			PRINT_ERROR("WaitForMultipleObjects failed\n");
			break;
		}

		// Exit event
		if (EventResult - WAIT_OBJECT_0 == 1)
		{
			goto end;
		}

		EnterCriticalSection(&ListCriticalSection);				
		if (IsListEmpty(FileList))
		{
			LeaveCriticalSection(&ListCriticalSection);
			goto end;
		}
		ListEntryDump = RemoveHeadList(FileList);
		NrFilesProcessed++;
		LeaveCriticalSection(&ListCriticalSection);

		ListItemDump = CONTAINING_RECORD(ListEntryDump, LIST_ITEM, ListEntry);
		ListItemParam = ListItemDump->Parameter;
		DumpExe(ListItemParam->SrcPath, ListItemParam->FileSize, ListItemParam->DestPath);

		free(ListItemParam);
		free(ListItemDump);
	}

	end:
	return STATUS_SUCCESS;
}

STATUS OpenFileForDump(LPSTR SrcPath, HANDLE *hIn)
{
	*hIn = CreateFile(
		SrcPath,
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

DWORD RvaToVa(PIMAGE_SECTION_HEADER SectionHeader, DWORD RVA, WORD NumberOfSections, DWORD FileSize)
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
				if (VA >= FileSize)
				{
					return 0;
				}
				return VA;
			}
		}
	}

	return 0;
}

STATUS PrintDumperHeader(LPSTR Filename, FILE* LogFile)
{
	fprintf(LogFile, "***********Dump of file info***********\n");
	fprintf(LogFile, "* Dumping: %s\n", Filename);

	return STATUS_SUCCESS;
}

STATUS CheckDos(PIMAGE_DOS_HEADER DosHeader, FILE* LogFile)
{
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		fprintf(LogFile, "DOS Header e_magic invalid!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

STATUS CheckPe(PIMAGE_DOS_HEADER DosHeader, PIMAGE_NT_HEADERS NtHeader, DWORD FileSize, FILE* LogFile)
{
	if (FileSize <= (DWORD)DosHeader->e_lfanew)
	{
		fprintf(LogFile, "No NT Header, it's probably an MS-DOS file, not a PE!\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		fprintf(LogFile, "NT Header signature invalid!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

STATUS IsI386(PIMAGE_FILE_HEADER FileHeader, FILE* LogFile)
{
	if (FileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		fprintf(LogFile, "Not a x86 exe!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

STATUS PrintDosHeaderInfo(PIMAGE_DOS_HEADER DosHeader, FILE* LogFile)
{
	fprintf(LogFile, "* DOS Header e_magic: %x (MZ)\n", DosHeader->e_magic);
	fprintf(LogFile, "* DOS Header e_lfanew: %x\n", DosHeader->e_lfanew);

	return STATUS_SUCCESS;
}

STATUS PrintNtHeaderInfo(PIMAGE_NT_HEADERS NtHeader, FILE* LogFile)
{
	fprintf(LogFile, "* NT Header Signature: %x (PE)\n", NtHeader->Signature);
	fprintf(LogFile, "***************************************\n");

	return STATUS_SUCCESS;
}

STATUS PrintFileHeaderInfo(PIMAGE_FILE_HEADER FileHeader, FILE* LogFile)
{
	fprintf(LogFile, "FILE HEADER\n");
	fprintf(LogFile, "   Machine: %x (Intel 386)\n", FileHeader->Machine);
	fprintf(LogFile, "   NumberOfSections: %x\n", FileHeader->NumberOfSections);
	fprintf(LogFile, "   TimeDateStamp: %x\n", FileHeader->TimeDateStamp);
	fprintf(LogFile, "   PointerToSymbolTable: %x\n", FileHeader->PointerToSymbolTable);
	fprintf(LogFile, "   NumberOfSymbols: %x\n", FileHeader->NumberOfSymbols);
	fprintf(LogFile, "   SizeOfOptionalHeader: %x\n", FileHeader->SizeOfOptionalHeader);
	fprintf(LogFile, "   Characteristics: %x\n", FileHeader->Characteristics);

	WORD Characteristics = FileHeader->Characteristics;
	if (IMAGE_FILE_DLL & Characteristics)
	{
		fprintf(LogFile, "       %s\n", "File is a DLL");
		Characteristics &= ~IMAGE_FILE_DLL;
	}
	if (IMAGE_FILE_SYSTEM & Characteristics)
	{
		fprintf(LogFile, "       %s\n", "System File");
		Characteristics &= ~IMAGE_FILE_SYSTEM;
	}
	if (IMAGE_FILE_32BIT_MACHINE & Characteristics)
	{
		fprintf(LogFile, "       %s\n", "32 bit word machine");
		Characteristics &= ~IMAGE_FILE_32BIT_MACHINE;
	}
	if (IMAGE_FILE_EXECUTABLE_IMAGE & Characteristics)
	{
		fprintf(LogFile, "       %s\n", "File is executable");
		Characteristics &= ~IMAGE_FILE_EXECUTABLE_IMAGE;
	}
	if (Characteristics)
	{
		fprintf(LogFile, "       %s\n", "+ Others");
	}
	fprintf(LogFile, "\n");

	return STATUS_SUCCESS;
}

STATUS PrintOptionalHeaderInfo(PIMAGE_OPTIONAL_HEADER OptionalHeader, FILE* LogFile)
{
	fprintf(LogFile, "OPTIONAL HEADER\n");
	fprintf(LogFile, "   Magic: %x (PE32)\n", OptionalHeader->Magic);
	fprintf(LogFile, "   SizeOfCode: %x\n", OptionalHeader->SizeOfCode);
	fprintf(LogFile, "   SizeOfInitializedData: %x\n", OptionalHeader->SizeOfInitializedData);
	fprintf(LogFile, "   SizeOfUninitializedData: %x\n", OptionalHeader->SizeOfUninitializedData);
	fprintf(LogFile, "   AdressOfEntryPoint: %x\n", OptionalHeader->AddressOfEntryPoint);
	fprintf(LogFile, "   BaseOfCode: %x\n", OptionalHeader->BaseOfCode); 
	fprintf(LogFile, "   BaseOfData: %x\n", OptionalHeader->BaseOfData);
	fprintf(LogFile, "   ImageBase: %x\n", OptionalHeader->ImageBase);
	fprintf(LogFile, "   SectionAlignment: %x\n", OptionalHeader->SectionAlignment);
	fprintf(LogFile, "   FileAlignment: %x\n", OptionalHeader->FileAlignment);
	fprintf(LogFile, "   Win32Version: %x\n", OptionalHeader->Win32VersionValue);
	fprintf(LogFile, "   SizeOfImage: %x\n", OptionalHeader->SizeOfImage);
	fprintf(LogFile, "   SizeOfHeaders: %x\n", OptionalHeader->SizeOfHeaders);
	fprintf(LogFile, "   CheckSum: %x\n", OptionalHeader->CheckSum);
	fprintf(LogFile, "   Subsystem %x ", OptionalHeader->Subsystem);

	if (IMAGE_SUBSYSTEM_WINDOWS_GUI == OptionalHeader->Subsystem)
	{
		fprintf(LogFile, "(Windows GUI)\n");
	}
	else if (IMAGE_SUBSYSTEM_WINDOWS_CUI == OptionalHeader->Subsystem)
	{
		fprintf(LogFile, "(Windows CUI)\n");
	}
	else if (IMAGE_SUBSYSTEM_NATIVE == OptionalHeader->Subsystem)
	{
		fprintf(LogFile, "(Native)\n");
	}
	
	fprintf(LogFile, "   DllCharacteristics: %x\n", OptionalHeader->DllCharacteristics);
	fprintf(LogFile, "   SizeOfStackReserve: %x\n", OptionalHeader->SizeOfStackReserve);
	fprintf(LogFile, "   SizeOfStackCommit: %x\n", OptionalHeader->SizeOfStackCommit);
	fprintf(LogFile, "   SizeOfHeapReserve: %x\n", OptionalHeader->SizeOfHeapReserve);
	fprintf(LogFile, "   SizeOfHeapCommit: %x\n", OptionalHeader->SizeOfHeapCommit);
	fprintf(LogFile, "   LoaderFlags: %x\n", OptionalHeader->LoaderFlags);
	fprintf(LogFile, "   NumberOfRvaAndSizes: %x\n", OptionalHeader->NumberOfRvaAndSizes);
	
	fprintf(LogFile, "       Export Directory RVA: %x\n       Export Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	fprintf(LogFile, "       Import Directory RVA: %x\n       Import Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	fprintf(LogFile, "       Resource Directory RVA: %x\n       Resource Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
	fprintf(LogFile, "       Exception Directory RVA: %x\n       Exception Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	fprintf(LogFile, "       Security Directory RVA: %x\n       Security Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	fprintf(LogFile, "       Relocation Directory RVA: %x\n       Relocation Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	fprintf(LogFile, "       Debug Directory RVA: %x\n       Debug Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	fprintf(LogFile, "       Architecture Directory RVA: %x\n       Architecture Directory: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
	fprintf(LogFile, "       TLS Directory RVA: %x\n       TLS Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	fprintf(LogFile, "       Configuration Directory RVA: %x\n       Configuration Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
	fprintf(LogFile, "       Bound Import Directory RVA: %x\n       Bound Import Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
	fprintf(LogFile, "       Import Address Table Directory RVA: %x\n       Import Address Table Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	fprintf(LogFile, "       Delay Import Directory RVA: %x\n       Delay Import Directory Size: %x\n", OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
	fprintf(LogFile, "\n");

	return STATUS_SUCCESS;
}

STATUS PrintSectionHeader(WORD Section, PIMAGE_SECTION_HEADER SectionHeader, PIMAGE_DOS_HEADER DosHeader, DWORD FileSize, FILE* LogFile)
{
	fprintf(LogFile, "SECTION HEADER #%d\n", Section + 1);

	DWORD Remaining = FileSize - ((PDWORD)SectionHeader - (PDWORD)DosHeader);
	if (sizeof(IMAGE_SECTION_HEADER)*Section > Remaining)
	{
		fprintf(LogFile, "   Section out of file!\n");
		return STATUS_UNSUCCESSFUL;
	}

	CHAR NameOfSection[255];
	if (strlen((char*)SectionHeader[Section].Name) > 8)
	{
		fprintf(LogFile, "   Invalid section name!\n");
	}
	else
	{
		strcpy_s(NameOfSection, strlen((char*)SectionHeader[Section].Name) + 1, (char*)SectionHeader[Section].Name);
	}

	fprintf(LogFile, "   NameOfSection: %s\n", NameOfSection);
	fprintf(LogFile, "   VirtualSize: %x\n", SectionHeader[Section].Misc.VirtualSize);
	fprintf(LogFile, "   SizeOfRawData: %x\n", SectionHeader[Section].SizeOfRawData);
	fprintf(LogFile, "   PointerToRelocations: %x\n", SectionHeader[Section].PointerToRelocations);
	fprintf(LogFile, "   PointerToLineNumbers: %x\n", SectionHeader[Section].PointerToLinenumbers);
	fprintf(LogFile, "   NumberOfRelocation: %x\n", SectionHeader[Section].NumberOfRelocations);
	fprintf(LogFile, "   NumberOfLinenumbers: %x\n", SectionHeader[Section].NumberOfLinenumbers);
	fprintf(LogFile, "   Characteristics: %x\n", SectionHeader[Section].Characteristics);

	DWORD Characteristics = SectionHeader[Section].Characteristics;
	if (IMAGE_SCN_CNT_CODE & Characteristics)
	{
		fprintf(LogFile, "   The section contains executable code.\n");
	}
	if (IMAGE_SCN_CNT_INITIALIZED_DATA & Characteristics)
	{
		fprintf(LogFile, "   The section contains initialized data.\n");
	}
	if (IMAGE_SCN_CNT_UNINITIALIZED_DATA & Characteristics)
	{
		fprintf(LogFile, "   The section contains uninitialized data.\n");
	}
	if (IMAGE_SCN_LNK_INFO & Characteristics)
	{
		fprintf(LogFile, "   The section contains comments or other information.\n");
	}
	if (IMAGE_SCN_MEM_SHARED & Characteristics)
	{
		fprintf(LogFile, "   The section can be shared in memory.\n");
	}
	if (IMAGE_SCN_MEM_EXECUTE & Characteristics)
	{
		fprintf(LogFile, "   The section can be executed as code.\n");
	}
	if (IMAGE_SCN_MEM_READ & Characteristics)
	{
		fprintf(LogFile, "   The section can be read.\n");
	}
	if (IMAGE_SCN_MEM_WRITE & Characteristics)
	{
		fprintf(LogFile, "   The section can be written to.\n");
	}

	fprintf(LogFile, "\n");

	return STATUS_SUCCESS;
}

STATUS PrintImportInfo(PIMAGE_OPTIONAL_HEADER OptionalHeader, PIMAGE_SECTION_HEADER SectionHeader, WORD NumberOfSections, PIMAGE_DOS_HEADER DosHeader, DWORD FileSize, FILE* LogFile)
{
	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 || !OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		fprintf(LogFile, "No imports\n\n");
		return STATUS_UNSUCCESSFUL;
	}

	DWORD ImportDescriptorRVA = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD ImportDescriptorVA = RvaToVa(SectionHeader, ImportDescriptorRVA, NumberOfSections, FileSize);
	if (!ImportDescriptorVA)
	{
		return STATUS_INVALID_RVA;
	}
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)DosHeader + ImportDescriptorVA);

	fprintf(LogFile, "IMPORTS\n");

	while (ImportDescriptor->Characteristics)
	{
		DWORD NameRVA = ImportDescriptor->Name;
		DWORD NameVA = RvaToVa(SectionHeader, NameRVA, NumberOfSections, FileSize);

		PDWORD Name;
		if (!NameVA)
		{
			Name = (PDWORD)"Invalid import DLL name";
		}
		else
		{
			Name = (PDWORD)(NameVA + (DWORD)DosHeader);
		}

		fprintf(LogFile, "   %s\n", (PCHAR)Name);
		fprintf(LogFile, "       Charatesritics: %x\n", ImportDescriptor->Characteristics);
		fprintf(LogFile, "       FirstThunkRVA: %x\n", ImportDescriptor->FirstThunk);
		fprintf(LogFile, "       OriginalFirstThunkRVA: %x\n", ImportDescriptor->OriginalFirstThunk);
		// Time is 0 until image is bound; fprintf(LogFile, "       Time: %x\n", ImportDescriptor->TimeDateStamp);
		// fprintf(LogFile, "       ForwarderChain: %x\n", ImportDescriptor->ForwarderChain);

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
		DWORD ImportLookupTableVA = RvaToVa(SectionHeader, ImportLookupTableRVA, NumberOfSections, FileSize);
		if (!ImportLookupTableVA)
		{
			return STATUS_INVALID_RVA;
		}
		PIMAGE_THUNK_DATA ImportLookupTable = (PIMAGE_THUNK_DATA)(ImportLookupTableVA + (DWORD)DosHeader);

		fprintf(LogFile, "\n       Imported Functions\n");
		while (ImportLookupTable->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL(ImportLookupTable->u1.Ordinal))
			{
				fprintf(LogFile, "          Imported by ordinal: %x\n", ImportLookupTable->u1.Ordinal); // Imported by ordinal
			}
			else
			{
				DWORD ImportByNameRVA = ImportLookupTable->u1.AddressOfData;
				DWORD ImportByNameVA = RvaToVa(SectionHeader, ImportByNameRVA, NumberOfSections, FileSize);
				if (!ImportByNameVA)
				{
					return STATUS_INVALID_RVA;
				}
				PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(ImportByNameVA + (DWORD)DosHeader);

				fprintf(LogFile, "          %x %s\n", ImportByName->Hint, ImportByName->Name);
			}
			ImportLookupTable++;
		}
		ImportDescriptor++;
		fprintf(LogFile, "\n");
	}

	return STATUS_SUCCESS;
}

STATUS PrintExportInfo(PIMAGE_OPTIONAL_HEADER OptionalHeader, PIMAGE_SECTION_HEADER SectionHeader, WORD NumberOfSections, PIMAGE_DOS_HEADER DosHeader, DWORD FileSize, FILE* LogFile)
{
	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || IMAGE_DIRECTORY_ENTRY_EXPORT >= OptionalHeader->NumberOfRvaAndSizes || !OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		fprintf(LogFile, "No exports\n\n");
		return STATUS_UNSUCCESSFUL;
	}

	DWORD ExportDirectoryRVA = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD ExportDirectoryVA = RvaToVa(SectionHeader, ExportDirectoryRVA, NumberOfSections, FileSize);
	if (!ExportDirectoryVA)
	{
		return STATUS_INVALID_RVA;
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportDirectoryVA + (DWORD)DosHeader);

	DWORD NameRVA = ExportDirectory->Name;
	DWORD NameVA = RvaToVa(SectionHeader, NameRVA, NumberOfSections, FileSize);
	PDWORD Name;
	if (!NameVA)
	{
		Name = (PDWORD)"Invalid Export DLL Name";
	}
	else 
	{
		Name = (PDWORD)(NameVA + (DWORD)DosHeader);
	}
	
	fprintf(LogFile, "EXPORTS\n");
	fprintf(LogFile, "   Name: %s\n", (char*)Name);
	fprintf(LogFile, "   Characteristics: %x\n", ExportDirectory->Characteristics);
	fprintf(LogFile, "   Time: %x\n", ExportDirectory->TimeDateStamp);
	fprintf(LogFile, "   Base: %x\n", ExportDirectory->Base);
	fprintf(LogFile, "   NumberOfFunctions: %x\n", ExportDirectory->NumberOfFunctions);
	fprintf(LogFile, "   NumberOfNames: %x\n", ExportDirectory->NumberOfNames);

	DWORD AdressOfFunctionsRVA = ExportDirectory->AddressOfFunctions;
	DWORD AdressOfFunctionsVA = RvaToVa(SectionHeader, AdressOfFunctionsRVA, NumberOfSections, FileSize);
	if (!AdressOfFunctionsVA)
	{
		return STATUS_INVALID_RVA;
	}
	PDWORD AdressOfFunctions = (PDWORD)(AdressOfFunctionsVA + (DWORD)DosHeader);

	DWORD AdressOfNamesRVA = ExportDirectory->AddressOfNames;
	DWORD AdressOfNamesVA = RvaToVa(SectionHeader, AdressOfNamesRVA, NumberOfSections, FileSize);
	if (!AdressOfNamesVA)
	{
		return STATUS_INVALID_RVA;
	}
	PDWORD AdressOfNames = (PDWORD)(AdressOfNamesVA + (DWORD)DosHeader);

	DWORD AdressOfNameOrdinalsRVA = ExportDirectory->AddressOfNameOrdinals;
	DWORD AdressOfNameOrdinalsVA = RvaToVa(SectionHeader, AdressOfNameOrdinalsRVA, NumberOfSections, FileSize);
	if (!AdressOfNameOrdinalsVA)
	{
		return STATUS_INVALID_RVA;
	}
	PWORD AdressOfNameOrdinals = (PWORD)(AdressOfNameOrdinalsVA + (DWORD)DosHeader);

	fprintf(LogFile, "\n   Exported Functions By Name\n");
	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
	//	if (AdressOfFunctions[AdressOfNameOrdinals[i]] < OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
	//		|| AdressOfFunctions[AdressOfNameOrdinals[i]] > OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
	//		+ OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
	//	{
		
		// Both exported and forwarded functions
		DWORD FunNameRVA = AdressOfNames[i];
		DWORD FunNameVA = RvaToVa(SectionHeader, FunNameRVA, NumberOfSections, FileSize);

		PDWORD FunName;
		if (!FunNameVA)
		{
			FunName = (PDWORD)"Unknown function name";
		}
		else
		{
			FunName = (PDWORD)(FunNameVA + (DWORD)DosHeader);
		}
		

		fprintf(LogFile, "       %s", (char*)FunName);
		fprintf(LogFile, " %x", AdressOfNameOrdinals[i] + ExportDirectory->Base);
		DWORD FunctionRVA = AdressOfFunctions[AdressOfNameOrdinals[i]];
		fprintf(LogFile, " %x\n", FunctionRVA);
	//	}
	}

	fprintf(LogFile, "\n   Exported Functions By Ordinal\n");
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
				fprintf(LogFile, "       %s", "No name");
				fprintf(LogFile, " %x\n", i + ExportDirectory->Base);
			}
		}
	}
	
	return STATUS_SUCCESS;
}

STATUS DumpExe(LPSTR SrcPath, DWORD FileSize, LPSTR DestPath)
{
	UNREFERENCED_PARAMETER(DestPath);

	FILE* LogFile = NULL;
	HANDLE hIn = INVALID_HANDLE_VALUE;
	HANDLE hMap = NULL;
	PIMAGE_DOS_HEADER DosHeader = NULL;

	if (!SUCCESS(OpenFileForDump(SrcPath, &hIn)))
	{
		PRINT_ERROR("CreateFile failed");
		goto cleanup;
	}

	if (!SUCCESS(MapFileForDump(hIn, &hMap)))
	{
		PRINT_ERROR("CreateFileMapping failed");
		if (GetLastError() == 1006)
		{
			printf("Cannot map an empty file!\n");
		}
		goto cleanup;
	}

	if (!SUCCESS(MapViewForDump(hMap, &DosHeader)))
	{
		PRINT_ERROR("MapViewOfFile failed");
		goto cleanup;
	}

	fopen_s(&LogFile, DestPath, "w");
	if (NULL == LogFile)
	{
		PRINT_ERROR("fopen failed");
		return STATUS_UNSUCCESSFUL;
	}

	PrintDumperHeader(SrcPath, LogFile);

	if (!SUCCESS(CheckDos(DosHeader, LogFile)))
	{
		goto cleanup;
	}

	PrintDosHeaderInfo(DosHeader, LogFile);

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + DosHeader->e_lfanew);

	if (!SUCCESS(CheckPe(DosHeader, NtHeader, FileSize, LogFile)))
	{
		goto cleanup;
	}

	PrintNtHeaderInfo(NtHeader, LogFile);

	PIMAGE_FILE_HEADER FileHeader = &NtHeader->FileHeader;

	if (!SUCCESS(IsI386(FileHeader, LogFile)))
	{
		goto cleanup;
	}

	if (FileSize <= (DWORD)FileHeader->SizeOfOptionalHeader)
	{
		fprintf(LogFile, "Invalid optional header!\n");
		goto cleanup;
	}

	PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)OptionalHeader + FileHeader->SizeOfOptionalHeader);

	PrintFileHeaderInfo(FileHeader, LogFile);
	PrintOptionalHeaderInfo(OptionalHeader, LogFile);

	for (WORD Section = 0; Section < FileHeader->NumberOfSections; Section++)
	{
		PrintSectionHeader(Section, SectionHeader, DosHeader, FileSize, LogFile);
	}

	PrintImportInfo(OptionalHeader, SectionHeader, FileHeader->NumberOfSections, DosHeader, FileSize, LogFile);
	PrintExportInfo(OptionalHeader, SectionHeader, FileHeader->NumberOfSections, DosHeader, FileSize, LogFile);
	
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
	if (LogFile != NULL)
	{
		fclose(LogFile);
	}

	return STATUS_SUCCESS;
}