#pragma once
#include "windows.h"

typedef struct
{
	CHAR SrcPath[2048];
	CHAR DestPath[2048];
	DWORD FileSize;
} LIST_ITEM_PARAM, *PLIST_ITEM_PARAM;

typedef struct
{
	PLIST_ITEM_PARAM Parameter;
	LIST_ENTRY ListEntry;
} LIST_ITEM, *PLIST_ITEM;

FORCEINLINE
	VOID
	InitializeListHead(
	__out PLIST_ENTRY ListHead
	)
{
	ListHead->Flink = ListHead->Blink = ListHead;
}

__checkReturn
	BOOLEAN
	FORCEINLINE
	IsListEmpty(
	__in const LIST_ENTRY * ListHead
	)
{
	return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
	BOOLEAN
	RemoveEntryList(
	__in PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Blink;
	PLIST_ENTRY Flink;

	Flink = Entry->Flink;
	Blink = Entry->Blink;
	Blink->Flink = Flink;
	Flink->Blink = Blink;
	return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
	PLIST_ENTRY
	RemoveHeadList(
	__inout PLIST_ENTRY ListHead
	)
{
	PLIST_ENTRY Flink;
	PLIST_ENTRY Entry;

	Entry = ListHead->Flink;
	Flink = Entry->Flink;
	ListHead->Flink = Flink;
	Flink->Blink = ListHead;
	return Entry;
}

FORCEINLINE
	PLIST_ENTRY
	RemoveTailList(
	__inout PLIST_ENTRY ListHead
	)
{
	PLIST_ENTRY Blink;
	PLIST_ENTRY Entry;

	Entry = ListHead->Blink;
	Blink = Entry->Blink;
	ListHead->Blink = Blink;
	Blink->Flink = ListHead;
	return Entry;
}


FORCEINLINE
	VOID
	InsertTailList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Blink;

	Blink = ListHead->Blink;
	Entry->Flink = ListHead;
	Entry->Blink = Blink;
	Blink->Flink = Entry;
	ListHead->Blink = Entry;
}


FORCEINLINE
	VOID
	InsertHeadList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Flink;

	Flink = ListHead->Flink;
	Entry->Flink = Flink;
	Entry->Blink = ListHead;
	Flink->Blink = Entry;
	ListHead->Flink = Entry;
}