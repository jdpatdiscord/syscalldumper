#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

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

LPCCH MachineEnumToString(DWORD Machine)
{
	switch(Machine)
	{
		case IMAGE_FILE_MACHINE_ALPHA64:
			return "IMAGE_FILE_MACHINE_ALPHA64";
		case IMAGE_FILE_MACHINE_ALPHA:
			return "IMAGE_FILE_MACHINE_ALPHA";
		case IMAGE_FILE_MACHINE_I386:
			return "IMAGE_FILE_MACHINE_I386";
		case IMAGE_FILE_MACHINE_AMD64:
			return "IMAGE_FILE_MACHINE_AMD64";
		case IMAGE_FILE_MACHINE_ARM64:
			return "IMAGE_FILE_MACHINE_ARM64";
		case IMAGE_FILE_MACHINE_ARMNT:
			return "IMAGE_FILE_MACHINE_ARMNT (Thumb)";
		case IMAGE_FILE_MACHINE_POWERPC:
			return "IMAGE_FILE_MACHINE_POWERPC (32-bit Little Endian)";
		case IMAGE_FILE_MACHINE_R3000:
			return "IMAGE_FILE_MACHINE_R3000 (MIPS)";
		case IMAGE_FILE_MACHINE_R4000:
			return "IMAGE_FILE_MACHINE_R4000 (MIPS)";
		case IMAGE_FILE_MACHINE_IA64:
			return "IMAGE_FILE_MACHINE_IA64";
		default:
			return "(Unknown image)";
	}
}

UINT_PTR Internal_ResolveRva64(PVOID FileBlock, DWORD dwRva)
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

UINT_PTR Internal_ResolveRva32(PVOID FileBlock, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS32 pNtHdr;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHdr;
	PIMAGE_FILE_HEADER pFileHdr;

	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr = (PIMAGE_NT_HEADERS32)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_OPTIONAL_HEADER32)(&pNtHdr->OptionalHeader);
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

BOOL IsRegionInText(PVOID FileBlock, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS32 pNtHdr;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHdr;
	PIMAGE_FILE_HEADER pFileHdr;

	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr = (PIMAGE_NT_HEADERS32)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_OPTIONAL_HEADER32)(&pNtHdr->OptionalHeader);
	pFileHdr = (PIMAGE_FILE_HEADER)(&pNtHdr->FileHeader);

	PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);

	BOOL result = FALSE;
	for (UINT i = 0; i < pFileHdr->NumberOfSections; ++i)
	{
		if (pSectionHdr[i].VirtualAddress + dwRva >= pSectionHdr[i].VirtualAddress &&
			pSectionHdr[i].VirtualAddress + dwRva <= pSectionHdr[i].VirtualAddress + pSectionHdr[i].SizeOfRawData &&
			!strncmp((const char*)pSectionHdr->Name, ".text", 5))
		{
			result = TRUE;
			break;
		}
	}
	return result;
}

#define RVA_AS(_tt, _coffhdr, _rva) ((_tt)(Internal_ResolveRva64(_coffhdr, _rva) + (UINT_PTR)_coffhdr))
#define RVA_32(_tt, _coffhdr, _rva) ((_tt)(Internal_ResolveRva32(_coffhdr, _rva) + (UINT_PTR)_coffhdr))

BOOL ExtractSyscallFromExportAMD64(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PCHAR Data = (PCHAR)FunctionAddress;
	if (*(DWORD*)(Data) == 0xB8D18B4C)
	{
		UINT SyscallNumber = *(DWORD*)(Data + 4);
		*pSyscallNumber = SyscallNumber;
		return TRUE;
	}
	return FALSE;
}

BOOL ExtractSyscallFromExportI386(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PUCHAR Data = (PUCHAR)FunctionAddress;
	if (*(Data) == 0xB8 && *(DWORD*)(Data + 5) == 0xFE0300BA)
	{
		UINT SyscallNumber = *(DWORD*)(Data + 1);
		*pSyscallNumber = SyscallNumber;
		return TRUE;
	}
	return FALSE;
}

BOOL ExtractSyscallFromExportARM64(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PCHAR Data = (PCHAR)FunctionAddress;
	DWORD SvcInstr = *(DWORD*)(Data);
	DWORD SvcOpMask    = 0b00000000000111111111111111100000;
	DWORD SvcInstrMask = 0b11010100000000000000000000000001;
	if ((SvcInstr & ~SvcOpMask) == SvcInstrMask)
	{
		*pSyscallNumber = (SvcInstr & SvcOpMask) >> 5;
		return TRUE;
	}
	return FALSE;
}

BOOL ExtractSyscallFromExportARMv7(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PCHAR Data = (PCHAR)FunctionAddress;
	DWORD LoadImm8Mask = 0b00000000000000001111111100000000;
	DWORD LoadImm8 = *(DWORD*)(Data);
	WORD SyscallInstr1 = *(WORD*)(Data + 4);
	if (SyscallInstr1 == 0x70DF)
	{
		*pSyscallNumber = (LoadImm8 & LoadImm8Mask) >> 8;
		return TRUE;
	}
	return FALSE;
}

BOOL ExtractSyscallFromExportMIPS32LE(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PCHAR Data = (PCHAR)FunctionAddress;
	DWORD LoadImm = *(DWORD*)(Data);
	DWORD SyscallInstr = *(DWORD*)(Data + 4);
	if (SyscallInstr == 0x0000000C)
	{
		*pSyscallNumber = LoadImm & 0x0000FFFF;
		return TRUE;
	}
	return FALSE;
}

BOOL ExtractSyscallFromExportPPC32LE(PVOID FunctionAddress, PUINT pSyscallNumber, PVOID FileBlock, DWORD FnOrd)
{
	PCHAR Data = (PCHAR)FunctionAddress;

	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS32 pNtHdr32;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHdr32;
	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr32 = (PIMAGE_OPTIONAL_HEADER32)(&pNtHdr32->OptionalHeader);

	PDWORD SyscallFnRef = (PDWORD)((PCHAR)FileBlock + (*(DWORD*)(Data) - pOptionalHdr32->ImageBase));
	DWORD SyscallNumber = *(DWORD*)(Data + 4);

	if (!IsRegionInText(FileBlock, FnOrd))
		return FALSE;

	if (*SyscallFnRef == 0x44000002)
	{
		*pSyscallNumber = SyscallNumber;
		return TRUE;
	}
	return FALSE;
}

BOOL ExtractSyscallFromExportAXP32(PVOID FunctionAddress, PUINT pSyscallNumber)
{
	PCHAR Data = (PCHAR)FunctionAddress;
	DWORD LoadImm = *(DWORD*)(Data);
	DWORD SyscallInstr = *(DWORD*)(Data + 4);
	if (SyscallInstr == 0x00000083)
	{
		*pSyscallNumber = LoadImm & 0x000000FF;
		return TRUE;
	}
	return FALSE;
}

void DumpSyscalls32(PVOID FileBlock)
{
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS32 pNtHdr32;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHdr32;
	PIMAGE_FILE_HEADER pFileHdr;

	static PCHAR IsAlreadyPresent[8192];
	ZeroMemory(&IsAlreadyPresent, sizeof(IsAlreadyPresent));

	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr32 = (PIMAGE_OPTIONAL_HEADER32)(&pNtHdr32->OptionalHeader);
	pFileHdr = (PIMAGE_FILE_HEADER)(&pNtHdr32->FileHeader);

	PIMAGE_DATA_DIRECTORY ExportDataDirectory = &pOptionalHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (ExportDataDirectory->Size)
	{
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = RVA_AS(PIMAGE_EXPORT_DIRECTORY, FileBlock, ExportDataDirectory->VirtualAddress);
		// printf(
		// 	"Characteristics: %08x\n"
		// 	"TimeDateStamp: %08x\n"
		// 	"MajorVersion: %04x\n"
		// 	"MinorVersion: %04x\n"
		// 	"Name: %08x\n"
		// 	"Base: %08x\n"
		// 	"NumberOfFunctions: %08x\n"
		// 	"NumberOfNames: %08x\n"
		// 	"AddressOfFunctions: %08x\n"
		// 	"AddressOfNames: %08x\n"
		// 	"AddressOfNameOrdinals: %08x\n",
		// 	ExportDirectory->Characteristics,
		// 	ExportDirectory->TimeDateStamp,
		// 	ExportDirectory->MajorVersion,
		// 	ExportDirectory->MinorVersion,
		// 	ExportDirectory->Name,
		// 	ExportDirectory->Base,
		// 	ExportDirectory->NumberOfFunctions,
		// 	ExportDirectory->NumberOfNames,
		// 	ExportDirectory->AddressOfFunctions,
		// 	ExportDirectory->AddressOfNames,
		// 	ExportDirectory->AddressOfNameOrdinals);

		PDWORD ExportNamePointerTable = RVA_32(PDWORD, FileBlock, ExportDirectory->AddressOfNames);
		PDWORD ExportFunctionPointerTable = RVA_32(PDWORD, FileBlock, ExportDirectory->AddressOfFunctions);
		PWORD ExportOrdinalPointerTable = RVA_32(PWORD, FileBlock, ExportDirectory->AddressOfNameOrdinals);

		UINT LastSyscallNumber = 0;
		for (UINT i = 0; i < ExportDirectory->NumberOfNames; ++i)
		{
			PCHAR Name = RVA_32(PCHAR, FileBlock, ExportNamePointerTable[i]);
			WORD Ordinal = ExportOrdinalPointerTable[i];
			PVOID FunctionAddress = RVA_32(PVOID, FileBlock, ExportFunctionPointerTable[Ordinal]);
			if (Ordinal > ExportDirectory->NumberOfFunctions)
				continue;

			UINT SyscallNumber;

			BOOL Success = FALSE;
			switch (pFileHdr->Machine)
			{
			case IMAGE_FILE_MACHINE_I386:
				Success = ExtractSyscallFromExportI386(FunctionAddress, &SyscallNumber);
				break;
			case IMAGE_FILE_MACHINE_R4000:
				Success = ExtractSyscallFromExportMIPS32LE(FunctionAddress, &SyscallNumber);
				break;
			case IMAGE_FILE_MACHINE_THUMB:
			case IMAGE_FILE_MACHINE_ARMNT:
				Success = ExtractSyscallFromExportARMv7(FunctionAddress, &SyscallNumber);
				break;
			case IMAGE_FILE_MACHINE_POWERPC:
				Success = ExtractSyscallFromExportPPC32LE(FunctionAddress, &SyscallNumber, FileBlock, ExportFunctionPointerTable[Ordinal]);
				break;
			case IMAGE_FILE_MACHINE_ALPHA:
				Success = ExtractSyscallFromExportAXP32(FunctionAddress, &SyscallNumber);
				break;
			default:
				printf("No valid machine!\n");
				break;
			}
			if (Success)
			{
				if (SyscallNumber >= _countof(IsAlreadyPresent))
				{
					printf("%s has flawed logic, or too many syscalls!\n", Name);
					continue;
				}
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
			//else
			//	printf("%u: (null)\n", i);
		}
	}
}

void DumpSyscalls64(PVOID FileBlock)
{
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS64 pNtHdr64;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHdr64;
	PIMAGE_FILE_HEADER pFileHdr;

	static PCHAR IsAlreadyPresent[8192];
	ZeroMemory(&IsAlreadyPresent, sizeof(IsAlreadyPresent));

	pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr64 = (PIMAGE_OPTIONAL_HEADER64)(&pNtHdr64->OptionalHeader);
	pFileHdr = (PIMAGE_FILE_HEADER)(&pNtHdr64->FileHeader);

	PIMAGE_DATA_DIRECTORY ExportDataDirectory = &pOptionalHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (ExportDataDirectory->Size)
	{
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = RVA_AS(PIMAGE_EXPORT_DIRECTORY, FileBlock, ExportDataDirectory->VirtualAddress);
		// printf(
		// 	"Characteristics: %08x\n"
		// 	"TimeDateStamp: %08x\n"
		// 	"MajorVersion: %04x\n"
		// 	"MinorVersion: %04x\n"
		// 	"Name: %08x\n"
		// 	"Base: %08x\n"
		// 	"NumberOfFunctions: %08x\n"
		// 	"NumberOfNames: %08x\n"
		// 	"AddressOfFunctions: %08x\n"
		// 	"AddressOfNames: %08x\n"
		// 	"AddressOfNameOrdinals: %08x\n",
		// 	ExportDirectory->Characteristics,
		// 	ExportDirectory->TimeDateStamp,
		// 	ExportDirectory->MajorVersion,
		// 	ExportDirectory->MinorVersion,
		// 	ExportDirectory->Name,
		// 	ExportDirectory->Base,
		// 	ExportDirectory->NumberOfFunctions,
		// 	ExportDirectory->NumberOfNames,
		// 	ExportDirectory->AddressOfFunctions,
		// 	ExportDirectory->AddressOfNames,
		// 	ExportDirectory->AddressOfNameOrdinals);

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

			BOOL Success = FALSE;
			switch (pFileHdr->Machine)
			{
			case IMAGE_FILE_MACHINE_AMD64:
				Success = ExtractSyscallFromExportAMD64(FunctionAddress, &SyscallNumber);
				break;
			case IMAGE_FILE_MACHINE_ARM64:
				Success = ExtractSyscallFromExportARM64(FunctionAddress, &SyscallNumber);
				break;
			default:
				break;
			}
			if (Success)
			{
				if (SyscallNumber >= _countof(IsAlreadyPresent))
				{
					printf("%s has flawed logic, or too many syscalls!\n", Name);
					continue;
				}
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
			//else
			//	printf("%u: (null)\n", i);
		}
	}

	return;
}

void DumpSyscalls(PVOID FileBlock)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)FileBlock;
	PIMAGE_NT_HEADERS64 pNtHdr64 = (PIMAGE_NT_HEADERS64)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	PIMAGE_NT_HEADERS32 pNtHdr32 = (PIMAGE_NT_HEADERS32)((PCHAR)pDosHdr + pDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER64 pOptionalHdr64 = (PIMAGE_OPTIONAL_HEADER64)(&pNtHdr64->OptionalHeader);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHdr32 = (PIMAGE_OPTIONAL_HEADER32)(&pNtHdr32->OptionalHeader);

	printf("Dumping for %s\n", MachineEnumToString(pNtHdr64->FileHeader.Machine));
	switch (pNtHdr64->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_AMD64:
	case IMAGE_FILE_MACHINE_ARM64:
	case IMAGE_FILE_MACHINE_ALPHA64:
	case IMAGE_FILE_MACHINE_SH5:
		printf("Image Base: %llX\n", pOptionalHdr64->ImageBase);
		DumpSyscalls64(FileBlock);
		break;
	default:
		printf("Image Base: %X\n", pOptionalHdr32->ImageBase);
		DumpSyscalls32(FileBlock);
		break;
	}
}

int main(int argc, char* argv[])
{
	if (argc <= 1)
		return 1;

	SIZE_T FileSize;
	PVOID FileBlock = INJ_ReadFile(argv[1], &FileSize);
	if (!FileBlock)
	{
		return 2;
	}

	DumpSyscalls(FileBlock);

	free(FileBlock);

	return 0;
}