#include "status_types.h"
#include "Shlwapi.h"
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Pathcch.lib")
#include "Pathcch.h"
#include "list.h"

//#define _CRTDBG_MAP_ALLOC  
//#include <stdlib.h>  
//#include <crtdbg.h> 

STATUS DumpExe(LPSTR SrcPath, DWORD FileSize, LPSTR DestPath);
DWORD WINAPI ListScanThreadFunction(
	_In_ LPVOID lpParameter);

DWORD NrFilesGiven = 0;
extern DWORD NrFilesProcessed;

CRITICAL_SECTION ListCriticalSection;
PLIST_ENTRY FileList = NULL;
HANDLE NewItemEvent = NULL;
HANDLE NoMoreFilesEvent = NULL;
HANDLE EndEvent = NULL;

DWORD WINAPI ExitCmdThreadFunction(
	_In_ LPVOID lpParameter)
{
	UNREFERENCED_PARAMETER(lpParameter);

listenCmd:
	printf("Give 'exit' command\n");
	CHAR cmd[256];
	scanf_s("%5s", cmd, 5);
	if (strcmp(cmd, "exit") == 0)
	{
		BOOL Result = SetEvent(EndEvent);
		if (FALSE == Result)
		{
			PRINT_ERROR("SetEvent failed");
			return 1;
		}
	}
	else
	{
		goto listenCmd;
	}

	return 0;
}

STATUS SearchDirectory(LPSTR Filename, BOOL Recursive, LPSTR Argument)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	BOOL Ok;
	CHAR OldDirectory[260];
	CHAR LogName[2047];
	LPSTR LogExt = ".log";
	PLIST_ITEM_PARAM ThreadParam = NULL;
	PLIST_ITEM ListItem = NULL;
	BOOL EventResult;
	LPSTR Extension;

	hFind = FindFirstFile(
		(LPCSTR)"*",
		&FindFileData);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("FindFirstFile failed");
		goto end;
	}

	if (GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		printf("No file found!\n");

		EventResult = SetEvent(NoMoreFilesEvent);
		if (FALSE == EventResult)
		{
			PRINT_ERROR("SetEvent failed");
		}

		goto end;
	}

	if (!strcmp(".", FindFileData.cFileName) || !strcmp("..", FindFileData.cFileName))
	{
		goto next_file;
	}

	Extension = PathFindExtension(FindFileData.cFileName);
	if (strcmp(Extension, ".log") == 0)
	{
		goto next_file;
	}

	if (FILE_ATTRIBUTE_DIRECTORY == FindFileData.dwFileAttributes)
	{
		if (Recursive)
		{
			if (0 == GetCurrentDirectory(260, (LPSTR)&OldDirectory))
			{
				PRINT_ERROR("GetCurrentDirectory failed");
				goto end;
			}

			if (0 == SetCurrentDirectory(FindFileData.cFileName))
			{
				PRINT_ERROR("SetCurrentDirectory failed");
				goto next_file;
			}

			CHAR SaveArgument[1024];
			strcpy_s(SaveArgument, strlen(Argument) + 1, Argument);
			PathRemoveFileSpec(SaveArgument);
			if (strlen(SaveArgument) != 0)
			{
				strcat_s(SaveArgument, strlen(SaveArgument) + 2, "\\");
			}
			strcat_s(SaveArgument, strlen(SaveArgument) + strlen(FindFileData.cFileName) + 1, FindFileData.cFileName);
			strcat_s(SaveArgument, strlen(SaveArgument) + 2, "\\");
			SearchDirectory(Filename, TRUE, SaveArgument);

			if (0 == SetCurrentDirectory(OldDirectory))
			{
				PRINT_ERROR("SetCurrentDirectory failed");
				goto end;
			}
		}
		goto next_file;
	}

	while (TRUE)
	{
		if (!PathMatchSpec(FindFileData.cFileName, Filename))
		{
			goto next_file;
		}
		else
		{
			//DumpExe(FindFileData);
			ThreadParam = (PLIST_ITEM_PARAM)malloc(sizeof(LIST_ITEM_PARAM));
			if (NULL == ThreadParam)
			{
				PRINT_ERROR("Malloc failed");
				return STATUS_UNSUCCESSFUL;
			}

			GetFullPathName(FindFileData.cFileName, (DWORD)sizeof(ThreadParam->SrcPath), (LPSTR)ThreadParam->SrcPath, NULL);

			strcpy_s(LogName, strlen(Argument) + 1, Argument);
			PathRemoveFileSpec(LogName);
			if (strlen(LogName) != 0)
			{
				strcat_s(LogName, strlen(LogName) + 2, "\\");
			}
			strcat_s(LogName, strlen(LogName) + strlen(FindFileData.cFileName) + 1, FindFileData.cFileName);
			strcat_s(LogName, strlen(LogName) + strlen(LogExt) + 1, LogExt);
			CHAR* pLog = LogName;
			while (*pLog)
			{
				if (*pLog == ':' || *pLog == '\\')
				{
					*pLog = '_';
				}
				pLog++;
			}

			CHAR ExePath[2048];
			GetModuleFileName(NULL, ExePath, 2048);
			PathRemoveFileSpec(ExePath);
			
			LPSTR DirName = "\\LogFiles";
			strcat_s(ExePath, strlen(ExePath) + strlen(DirName) + 1, DirName);
			BOOL Result = CreateDirectory(
				ExePath,
				NULL);

			if (FALSE == Result && GetLastError() == ERROR_PATH_NOT_FOUND)
			{
				return STATUS_UNSUCCESSFUL;
			}

			strcat_s(ExePath, strlen(ExePath) + 2, "\\");
			strcat_s(ExePath, strlen(ExePath) + strlen(LogName) + 1, LogName);
			strcpy_s(ThreadParam->DestPath, strlen(ExePath) + 1, ExePath);
			
			//GetFullPathName(LogName, (DWORD)sizeof(ThreadParam->DestPath), (LPSTR)ThreadParam->DestPath, NULL);

			ThreadParam->FileSize = FindFileData.nFileSizeLow;

			ListItem = (PLIST_ITEM)malloc(sizeof(LIST_ITEM));
			if (NULL == ListItem)
			{
				PRINT_ERROR("Malloc failed");
				return STATUS_UNSUCCESSFUL;
			}
			
			ListItem->Parameter = ThreadParam;

			EnterCriticalSection(&ListCriticalSection);
			InsertHeadList(FileList, &ListItem->ListEntry);
			LeaveCriticalSection(&ListCriticalSection);

			EventResult = SetEvent(NewItemEvent);
			if (FALSE == EventResult)
			{
				PRINT_ERROR("SetEvent error");
				return STATUS_UNSUCCESSFUL;
			}

			NrFilesGiven++;
		}

	next_file:
		Ok = FindNextFile(
			hFind,
			&FindFileData);

		if (!Ok && GetLastError() == ERROR_NO_MORE_FILES)
		{
			goto end;
		}
		else if (!Ok)
		{
			PRINT_ERROR("Unexpected error");
			goto end;
		}

		if (!strcmp(".", FindFileData.cFileName) || !strcmp("..", FindFileData.cFileName))
		{
			goto next_file;
		}

		Extension = PathFindExtension(FindFileData.cFileName);
		if (strcmp(Extension, ".log") == 0)
		{
			goto next_file;
		}

		if (FILE_ATTRIBUTE_DIRECTORY == FindFileData.dwFileAttributes)
		{
			if (Recursive)
			{
				if (0 == GetCurrentDirectory(260, (LPSTR)(&OldDirectory)))
				{
					PRINT_ERROR("GetCurrentDirectory failed");
					goto end;
				}

				if (0 == SetCurrentDirectory(FindFileData.cFileName))
				{
					PRINT_ERROR("SetCurrentDirectory failed");
					goto next_file;
				}

				CHAR SaveArgument[1024];
				strcpy_s(SaveArgument, strlen(Argument) + 1, Argument);
				PathRemoveFileSpec(SaveArgument);
				if (strlen(SaveArgument) != 0)
				{
					strcat_s(SaveArgument, strlen(SaveArgument) + 2, "\\");
				}
				strcat_s(SaveArgument, strlen(SaveArgument) + strlen(FindFileData.cFileName) + 1, FindFileData.cFileName);
				strcat_s(SaveArgument, strlen(SaveArgument) + 2, "\\");
				SearchDirectory(Filename, TRUE, SaveArgument);

				if (0 == SetCurrentDirectory(OldDirectory))
				{
					PRINT_ERROR("SetCurrentDirectory failed");
					goto end;
				}
			}
			goto next_file;
		}
	}

end:
	if (INVALID_HANDLE_VALUE != hFind)
	{
		FindClose(hFind);
	}

	return STATUS_SUCCESS;
}

int main(int argc, char *argv[])
{
	BOOL Recursive = FALSE;
	DWORD NumberOfThreads = 8;
	HANDLE *Threads = NULL;

	if (argc < 2)
	{
		printf("Usage: PE-Dumper.exe path/filename/pattern [r] [nr. of threads]\n");
		return 0;
	}
	else if (argc == 2)
	{
		Recursive = FALSE;
	}
	else if (argc == 3)
	{
		DWORD nr = atoi(argv[2]);
		if (nr)
		{
			NumberOfThreads = nr;
		}
		else if (strcmp("r", argv[2]) == 0)
		{
			Recursive = TRUE;
		}
	}
	else
	{
		DWORD nr = atoi(argv[2]);
		DWORD nr2 = atoi(argv[3]);
		if (nr)
		{
			NumberOfThreads = nr;
		}
		else if (nr2)
		{
			NumberOfThreads = nr2;
		}
		if (strcmp("r", argv[2]) == 0)
		{
			Recursive = TRUE;
		}
		else if (strcmp("r", argv[3]) == 0)
		{
			Recursive = TRUE;
		}
	}

	
	FileList = (PLIST_ENTRY)malloc(sizeof(LIST_ENTRY));
	if (NULL == FileList)
	{
		PRINT_ERROR("Malloc failed");
		goto cleanup;
	}

	InitializeListHead(FileList);
	InitializeCriticalSection(&ListCriticalSection);

	NewItemEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (NULL == NewItemEvent)
	{
		PRINT_ERROR("CreateEvent failed");
		goto cleanup;
	}

	NoMoreFilesEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == NoMoreFilesEvent)
	{
		PRINT_ERROR("CreateEvent failed");
		goto cleanup;
	}

	EndEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == EndEvent)
	{
		PRINT_ERROR("CreateEvent failed");
		goto cleanup;
	}

	Threads = (HANDLE*)malloc(sizeof(HANDLE) * NumberOfThreads);
	if (NULL == Threads)
	{
		PRINT_ERROR("Malloc failed");
		goto cleanup;
	}

	for (DWORD Thread = 0; Thread < NumberOfThreads; Thread++)
	{
		Threads[Thread] = CreateThread(NULL, 0, ListScanThreadFunction, NULL, 0, NULL);
		if (NULL == Threads[Thread])
		{
			PRINT_ERROR("CreateThread failed!");
			goto cleanup;
		}
	}

	if (PathIsFileSpec(argv[1]))
	{
		SearchDirectory(argv[1], Recursive, argv[1]);
	}
	else
	{
		LPSTR FileSpecPointer = PathFindFileName(argv[1]);
		CHAR File[255];
		strcpy_s(File, strlen(FileSpecPointer) + 1, FileSpecPointer);

		CHAR Path[255];
		strcpy_s(Path, strlen(argv[1]) + 1, argv[1]);
		PathRemoveFileSpec(Path);

		if (0 == SetCurrentDirectory(Path))
		{
			PRINT_ERROR("SetCurrentDirectory failed");
			goto cleanup;
		}

		SearchDirectory(File, Recursive, argv[1]);
	}

	BOOL EventResult = SetEvent(NoMoreFilesEvent);
	if (FALSE == EventResult)
	{
		PRINT_ERROR("SetEvent failed");
		goto cleanup;
	}

	HANDLE ExitCmdThread = CreateThread(NULL, 0, ExitCmdThreadFunction, NULL, 0, NULL);
	if (NULL == ExitCmdThread)
	{
		PRINT_ERROR("CreateThread failed");
		goto cleanup;
	}

cleanup:
	WaitForMultipleObjects(NumberOfThreads, Threads, TRUE, INFINITE);
	DeleteCriticalSection(&ListCriticalSection);
	if (Threads != NULL)
	{
		free(Threads);
	}
	while (!IsListEmpty(FileList) && FileList != NULL)
	{
		PLIST_ENTRY ListEntryDump = RemoveHeadList(FileList);
		PLIST_ITEM ListItemDump = CONTAINING_RECORD(ListEntryDump, LIST_ITEM, ListEntry);
		PLIST_ITEM_PARAM ListItemParam = ListItemDump->Parameter;
	
		free(ListItemParam);
		free(ListItemDump);
	}
	if (FileList != NULL)
	{
		free(FileList);
	}
	if (NewItemEvent != NULL)
	{
		CloseHandle(NewItemEvent);
	}
	if (NoMoreFilesEvent != NULL)
	{
		CloseHandle(NoMoreFilesEvent);
	}
	if (EndEvent != NULL)
	{
		CloseHandle(EndEvent);
	}

	//_CrtDumpMemoryLeaks();

	printf("\n\nNumber of files dumped: %d\n", NrFilesProcessed);
	return STATUS_SUCCESS;
}