#include "status_types.h"
#include "Shlwapi.h"
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Pathcch.lib")
#include "Pathcch.h"

STATUS DumpExe(WIN32_FIND_DATA File);

DWORD NrFiles = 0;

STATUS SearchDirectory(LPSTR Filename, BOOL Recursive)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	BOOL Ok;
	CHAR OldDirectory[260];

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
		goto end;
	}

	if (!strcmp(".", FindFileData.cFileName) || !strcmp("..", FindFileData.cFileName))
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

			SearchDirectory(Filename, TRUE);

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
			DumpExe(FindFileData);
			NrFiles++;
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

				SearchDirectory(Filename, TRUE);

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
	BOOL Recursive;

	if (argc < 2)
	{
		printf("Usage: pedumper.exe filename/filepattern recursive(opt)\n");
		return 0;
	}
	else if (argc == 2)
	{
		Recursive = FALSE;
	}
	else
	{
		Recursive = TRUE;
	}

	if (PathIsFileSpec(argv[1]))
	{
		SearchDirectory(argv[1], Recursive);
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
			return STATUS_UNSUCCESSFUL;
		}
		SearchDirectory(File, Recursive);
	}

	printf("\n\nNumber of files dumped: %d\n", NrFiles);
	return 0;
}