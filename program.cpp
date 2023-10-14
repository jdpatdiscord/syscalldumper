#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include <Zydis/Zydis.h>

PVOID INJ_ReadFile(LPCCH szFileName, PSIZE_T pFileSize)
{
	FILE* pFileHandle = fopen(szFileName, "rb");
	if (!pFileHandle)
	{
		return 0;
	}
	fseek(pFileHandle, 0, SEEK_END);
	SIZE_T qwFileSize = ftell(pFileHandle);
	PVOID pFileBuffer = malloc(qwFileSize);
	fseek(pFileHandle, 0, SEEK_SET);
	if (!pFileBuffer)
	{
		fclose(pFileHandle);
		return 0;
	}
	SIZE_T qwBytesRead = fread(pFileBuffer, 1, qwFileSize, pFileHandle);
	if (qwBytesRead != qwFileSize)
	{
		fclose(pFileHandle);
		free(pFileBuffer);
		return 0;
	};
	fclose(pFileHandle);
	*pFileSize = qwFileSize;
	return pFileBuffer;
}

UINT_PTR Internal_ResolveRva(PVOID FileBlock, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS pNtHdr;
	PIMAGE_OPTIONAL_HEADER pOptionalHdr;
	PIMAGE_FILE_HEADER pFileHdr;

	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr = (PIMAGE_NT_HEADERS)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_OPTIONAL_HEADER)(&pNtHdr->OptionalHeader);
	pFileHdr = (PIMAGE_FILE_HEADER)(&pNtHdr->FileHeader);

	PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);

	UINT_PTR result = 0;
	for (UINT i = 0; i < pFileHdr->NumberOfSections; ++i)
	{
		if (dwRva >= pSectionHdr[i].VirtualAddress &&
			dwRva <= pSectionHdr[i].VirtualAddress + pSectionHdr[i].SizeOfRawData)
		{
			result = pSectionHdr[i].PointerToRawData + dwRva - pSectionHdr[i].VirtualAddress;
			break;
		}
	}

	return result;
}

#define RVA_AS(_tt, _coffhdr, _rva) ((_tt)(Internal_ResolveRva(_coffhdr, _rva) + (UINT_PTR)_coffhdr))

BOOL ExtractSyscallFromExport(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PCHAR Data = (PCHAR)FunctionAddress;
	if ( *(DWORD*)(Data) == 0xB8D18B4C )
	{
		UINT SyscallNumber = *(DWORD*)(Data + 4);
		*pSyscallNumber = SyscallNumber;
		return TRUE;
	}
	return FALSE;
}

int main(int argc, char* argv[])
{
	//if (argc <= 1)
	//	return 1;

	SIZE_T FileSize;
	PVOID FileBlock = INJ_ReadFile("C:\\Windows\\System32\\ntdll.dll", &FileSize);
	if (!FileBlock)
	{
		return 2;
	}

	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS pNtHdr;
	PIMAGE_OPTIONAL_HEADER pOptionalHdr;
	PIMAGE_FILE_HEADER pFileHdr;

	PCHAR IsAlreadyPresent[1024];
	ZeroMemory(&IsAlreadyPresent, sizeof(IsAlreadyPresent));

	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr = (PIMAGE_NT_HEADERS)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_OPTIONAL_HEADER)(&pNtHdr->OptionalHeader);
	pFileHdr = (PIMAGE_FILE_HEADER)(&pNtHdr->FileHeader);

	PIMAGE_DATA_DIRECTORY ExportDataDirectory = &pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (ExportDataDirectory->Size)
	{
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = RVA_AS(PIMAGE_EXPORT_DIRECTORY, FileBlock, ExportDataDirectory->VirtualAddress);
		printf(
			"Characteristics: %08x\n"
			"TimeDateStamp: %08x\n"
			"MajorVersion: %04x\n"
			"MinorVersion: %04x\n"
			"Name: %08x\n"
			"Base: %08x\n"
			"NumberOfFunctions: %08x\n"
			"NumberOfNames: %08x\n"
			"AddressOfFunctions: %08x\n"
			"AddressOfNames: %08x\n"
			"AddressOfNameOrdinals: %08x\n",
			ExportDirectory->Characteristics,
			ExportDirectory->TimeDateStamp,
			ExportDirectory->MajorVersion,
			ExportDirectory->MinorVersion,
			ExportDirectory->Name,
			ExportDirectory->Base,
			ExportDirectory->NumberOfFunctions,
			ExportDirectory->NumberOfNames,
			ExportDirectory->AddressOfFunctions,
			ExportDirectory->AddressOfNames,
			ExportDirectory->AddressOfNameOrdinals);
		
		PDWORD ExportNamePointerTable = RVA_AS(PDWORD, FileBlock, ExportDirectory->AddressOfNames);
		PDWORD ExportFunctionPointerTable = RVA_AS(PDWORD, FileBlock, ExportDirectory->AddressOfFunctions);
		PWORD ExportOrdinalPointerTable = RVA_AS(PWORD, FileBlock, ExportDirectory->AddressOfNameOrdinals);

		UINT LastSyscallNumber = 0;
		for (UINT i = 0; i < ExportDirectory->NumberOfNames; ++i)
		{
			PCHAR Name = RVA_AS(PCHAR, FileBlock, ExportNamePointerTable[i]);
			WORD Ordinal = ExportOrdinalPointerTable[i];
			PVOID FunctionAddress = RVA_AS(PVOID, FileBlock, ExportFunctionPointerTable[Ordinal]);

			UINT SyscallNumber;
			if (ExtractSyscallFromExport(FunctionAddress, &SyscallNumber))
			{
				if (IsAlreadyPresent[SyscallNumber])
					continue;

				// print here for in order alphabetically

				IsAlreadyPresent[SyscallNumber] = Name;
				if (SyscallNumber > LastSyscallNumber)
					LastSyscallNumber = SyscallNumber;
			}
		}

		for (UINT i = 0; i < LastSyscallNumber; ++i)
		{
			// print here for in order numerically
			
			if (IsAlreadyPresent[i])
				printf("%u: %s\n", i, IsAlreadyPresent[i]);
			else
				printf("%u: (null)\n", i);
		}
	}

    

	return 0;
}