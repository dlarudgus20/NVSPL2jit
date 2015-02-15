// Copyright (c) 2015, ÀÓ°æÇö
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met :
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and / or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "stdafx.h"
#include "output.h"

void output(uint8_t *code, uint8_t *end, char *fname)
{
	IMAGE_DOS_HEADER dos_header;
	ZeroMemory(&dos_header, sizeof(dos_header));
	dos_header.e_magic = 'MZ';
	dos_header.e_lfanew = sizeof(dos_header);

	IMAGE_NT_HEADERS32 headers;
	ZeroMemory(&headers, sizeof(headers));
	headers.Signature = 'PE\0\0';

	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	LARGE_INTEGER li;
	li.HighPart = ft.dwHighDateTime;
	li.LowPart = ft.dwLowDateTime;
	DWORD time = (DWORD)(li.QuadPart / 10000000);

	headers.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	headers.FileHeader.NumberOfSections = 42; // TODO
	headers.FileHeader.TimeDateStamp = time;
	headers.FileHeader.PointerToSymbolTable = 0;
	headers.FileHeader.NumberOfSymbols = 0;
	headers.FileHeader.SizeOfOptionalHeader = sizeof(headers.OptionalHeader);
	headers.FileHeader.Characteristics =
		IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;

	headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	headers.OptionalHeader.MajorLinkerVersion = 1;
	headers.OptionalHeader.MinorLinkerVersion = 0;
	headers.OptionalHeader.SizeOfCode = 42; // TODO
	headers.OptionalHeader.SizeOfInitializedData = 42; // TODO
	headers.OptionalHeader.SizeOfUninitializedData = 42; // TODO
	headers.OptionalHeader.AddressOfEntryPoint = 42; // TODO
	headers.OptionalHeader.BaseOfCode = 42; // TODO
	headers.OptionalHeader.BaseOfData = 42; // TODO
	headers.OptionalHeader.ImageBase = 0x00400000;
	headers.OptionalHeader.SectionAlignment = 4096;
	headers.OptionalHeader.FileAlignment = 512;
	headers.OptionalHeader.MajorOperatingSystemVersion = 6;
	headers.OptionalHeader.MinorOperatingSystemVersion = 0;
	headers.OptionalHeader.MajorImageVersion = 1;
	headers.OptionalHeader.MinorImageVersion = 0;
	headers.OptionalHeader.MajorSubsystemVersion = headers.OptionalHeader.MajorOperatingSystemVersion;
	headers.OptionalHeader.MinorSubsystemVersion = headers.OptionalHeader.MinorOperatingSystemVersion;
	headers.OptionalHeader.SizeOfImage = 42; // TODO
	headers.OptionalHeader.SizeOfHeaders = sizeof(dos_header.e_lfanew) + sizeof(headers);
	headers.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	headers.OptionalHeader.SizeOfStackReserve = 1024 * 1024;
	headers.OptionalHeader.SizeOfStackCommit = 4 * 1024;
	headers.OptionalHeader.SizeOfHeapReserve = 1024 * 1024;
	headers.OptionalHeader.SizeOfHeapCommit = 4 * 1024;
	headers.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	IMAGE_SECTION_HEADER secheaders[10];
	ZeroMemory(secheaders, sizeof(secheaders));

	memcpy(secheaders[0].Name, ".text", 5);
	secheaders[0].Misc.VirtualSize = 42; // TODO
	secheaders[0].VirtualAddress = 42; // TODO
	secheaders[0].SizeOfRawData = 42; // TODO
	secheaders[0].PointerToRawData = 42; // TODO
	secheaders[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

	memcpy(secheaders[1].Name, ".data", 5);
	secheaders[1].Misc.VirtualSize = 42; // TODO
	secheaders[1].VirtualAddress = 42; // TODO
	secheaders[1].SizeOfRawData = 42; // TODO
	secheaders[1].PointerToRawData = 42; // TODO
	secheaders[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	memcpy(secheaders[2].Name, ".idata", 5);
	secheaders[2].Misc.VirtualSize = 42; // TODO
	secheaders[2].VirtualAddress = 42; // TODO
	secheaders[2].SizeOfRawData = 42; // TODO
	secheaders[2].PointerToRawData = 42; // TODO
	secheaders[2].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
}
