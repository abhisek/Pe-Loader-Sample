#ifndef _PE_LDR_H
#define _PE_LDR_H

#include <windows.h>
#include <tchar.h>
#include <winnt.h>

typedef struct {
	TCHAR					*pTargetPath;
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;

	BOOLEAN					bLoadFromBuffer;
	DWORD					dwImage;
	DWORD					dwImageSizeOnDisk;

	DWORD					dwLoaderBase;
	DWORD					dwLoaderRelocatedBase;

	DWORD					dwMapBase;

} PE_LDR_PARAM;

VOID PeLdrInit(PE_LDR_PARAM *pe);
BOOL PeLdrSetExecutablePath(PE_LDR_PARAM *pe, TCHAR *pExecutable);
BOOL PeLdrSetExecutableBuffer(PE_LDR_PARAM *pe, PVOID pExecutable, DWORD dwLen);
BOOL PeLdrStart(PE_LDR_PARAM *pe);

#endif