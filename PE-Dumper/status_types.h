#pragma once
#include <stdio.h>
#include <windows.h>

extern CRITICAL_SECTION ListCriticalSection;
extern PLIST_ENTRY FileList;
extern HANDLE NewItemEvent;
extern HANDLE NoMoreFilesEvent;
extern HANDLE EndEvent;


// #ifndef BOOLEAN
// typedef unsigned __int8 BOOLEAN, *PBOOLEAN;
// #endif

#ifndef STATUS
typedef int STATUS;
#endif // !STATUS

// #ifndef NULL
// #define NULL ((void *)0)
// #endif

// Statuses values
// Generic
#define     STATUS_SUCCESS                          0
#define     STATUS_UNSUCCESSFUL                     -1
#define     STATUS_INVALID_PARAMETER_1              -2
#define     STATUS_INVALID_PARAMETER_2              -3
#define     STATUS_INVALID_PARAMETER_3              -4
#define     STATUS_INVALID_PARAMETER_4              -5
#define		STATUS_CREATE_FILE_FAILED				-6
#define		STATUS_MAPPING_FAILED					-7
#define		STATUS_MAPVIEW_FAILED					-8
#define		STATUS_INVALID_RVA						-9
#define		STATUS_CHECKPE_FAILED					-10

#define     SUCCESS(Status)                         (0 == Status)

#define PRINT_ERROR(x) printf("%s\nError code: %d\n", x, GetLastError());