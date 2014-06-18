/*
 * grml-plus UEFI protector - protect UEFI against bricking memory map
 *
 * Copyright 2014, Michael Schierl <schierlm@gmx.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <efi.h>
#include <efilib.h>

static void printColor(UINTN color, CHAR16* string) {
    uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, color);
    Print(string);
}

static void runImage(EFI_HANDLE ImageHandle, CHAR16* filename) {
    EFI_GUID loadedImageProtocol = LOADED_IMAGE_PROTOCOL;
    EFI_LOADED_IMAGE *li;
    EFI_HANDLE newImage;
    CHAR16 *pathname = NULL;
    CHAR16 *myname;
    INTN i;

    uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle, &loadedImageProtocol, (void **)&li);
    myname = DevicePathToStr(li->FilePath);
    for (i = StrLen(myname); i > 0 && myname[i] != L'\\'; i--) ;
    if (i > 0 && myname[i-1] != L'\\') i++;
    myname[i] = '\0';
    pathname = AllocateZeroPool(StrLen(myname) + StrLen(filename) + 1);
    StrCat(pathname, myname);
    StrCat(pathname, filename);
    uefi_call_wrapper(BS->LoadImage, 6, FALSE, ImageHandle, FileDevicePath(li->DeviceHandle, pathname), NULL, 0, &newImage);
    uefi_call_wrapper(BS->StartImage, 3, newImage, NULL, NULL);
    FreePool(myname);
    FreePool(pathname);
}

static BOOLEAN memoryTypeInformationVariableFound() {
    EFI_GUID memoryTypeInformationGUID = { 0x4c19049f,0x4137,0x4dd3, { 0x9c,0x10,0x8b,0x97,0xa8,0x3f,0xfd,0xfa } };
    UINTN dataSize = 0, dummy;
    EFI_STATUS status = uefi_call_wrapper(RT->GetVariable, 5, L"MemoryTypeInformation",
        &memoryTypeInformationGUID, NULL, &dataSize, &dummy);
    return status != EFI_NOT_FOUND;
}

static void guruScreen() {
    EFI_GUID memoryTypeInformationGUID = { 0x4c19049f,0x4137,0x4dd3, { 0x9c,0x10,0x8b,0x97,0xa8,0x3f,0xfd,0xfa } };
    UINTN i, j, DescriptorSize;
    UINT32 DescriptorVersion;
    UINT64 NoPages[EfiMaxMemoryType];
    INT32 StoredPages[2][EfiMaxMemoryType];
    UINT32 buffer[40];
    EFI_MEMORY_DESCRIPTOR *Desc, *MemMap;
    UINTN dataSize;
    EFI_STATUS status;

    for(i = 0; i < EfiMaxMemoryType; i++) {
        NoPages[i] = 0;
        StoredPages[0][i] = -1;
        StoredPages[1][i] = -1;
    }

    for(j = 0; j < 2; j++) {
        dataSize = 160;
        status = uefi_call_wrapper(RT->GetVariable, 5, 
            j ? L"MemoryTypeInformationBackup" : L"MemoryTypeInformation",
            &memoryTypeInformationGUID, NULL, &dataSize, &buffer);
        if (status == EFI_SUCCESS) {
            for(i = 0; i < (dataSize >> 2); i += 2) {
                if(buffer[i] >= 0 && buffer[i] < EfiMaxMemoryType) {
                    StoredPages[j][buffer[i]] = buffer[i+1];
                }
            }
        }
    }

    MemMap = LibMemoryMap (&j, &i, &DescriptorSize, &DescriptorVersion);
    Desc = MemMap;
    for (i = 0; i < j; i++) {
        NoPages[Desc->Type] += Desc->NumberOfPages;
        Desc = NextMemoryDescriptor(Desc, DescriptorSize);
    }
    Print(L"Type  Used      Stored    Backup\n");
    for (i = 0; i < EfiMaxMemoryType; i++) {
        if (NoPages[i] != 0 || StoredPages[0][i] != -1 || StoredPages[1][i] != -1) {
            Print(L"%04x  %08lx  %08x  %08x\n", i, NoPages[i], StoredPages[0][i], StoredPages[1][i]);
        }
    }
    WaitForSingleEvent(ST->ConIn->WaitForKey, 0);
}

EFI_STATUS EFIAPI efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    EFI_INPUT_KEY key;
    BOOLEAN mayExit = TRUE, imageStarted;

    InitializeLib(ImageHandle, SystemTable);

    while(TRUE) {
        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
        printColor(EFI_LIGHTRED, L"grml-plus UEFI Protector\n");
        printColor(EFI_LIGHTBLUE, L"(c) 2014 Michael Schierl\n\n");
        printColor(EFI_LIGHTCYAN, L"C"); printColor(EFI_WHITE, L"ontinue booting to GRUB bootloader\n\n");
        printColor(EFI_LIGHTCYAN, L"M"); printColor(EFI_WHITE, L"emtest\n");
        printColor(EFI_LIGHTCYAN, L"E"); printColor(EFI_WHITE, L"FI Shell\n");
        printColor(EFI_LIGHTCYAN, L"U"); printColor(EFI_WHITE, L"EFI Shell\n\n");
        printColor(EFI_LIGHTCYAN, L"R"); printColor(EFI_WHITE, L"eboot\n");
        printColor(EFI_LIGHTCYAN, L"H"); printColor(EFI_WHITE, L"alt\n\n");

        if (mayExit) {
            printColor(EFI_LIGHTCYAN, L"Q"); printColor(EFI_WHITE, L"uit\n\n\n");
        } else {
            printColor(EFI_YELLOW, L"\n(Quit command disabled to avoid bricking memory map)\n");
            printColor(EFI_WHITE, L"\n");
        }

        WaitForSingleEvent(ST->ConIn->WaitForKey, 0);
        uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &key);

        if (key.UnicodeChar == 0 && key.ScanCode == SCAN_ESC) {
            key.UnicodeChar = L'Q';
        }

        imageStarted = FALSE;

        switch (key.UnicodeChar) {
            case L'c':
            case L'C':
            case L'\r':
            case L' ':
                imageStarted = TRUE;
                runImage(ImageHandle, L"grub.efi");
                break;

            case L'M':
            case L'm':
                imageStarted = TRUE;
                runImage(ImageHandle, L"memtest.efi");
                break;

            case L'E':
            case L'e':
                imageStarted = TRUE;
                runImage(ImageHandle, L"efi-shell.efi");
                break;

            case L'u':
            case L'U':
                imageStarted = TRUE;
                runImage(ImageHandle, L"uefi-shell.efi");
                break;

            case L'r':
            case L'R':
                imageStarted = TRUE;
                uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS, 0, NULL);
                break;

            case L'h':
            case L'H':
                imageStarted = TRUE;
                uefi_call_wrapper(RT->ResetSystem, 4, EfiResetShutdown, EFI_SUCCESS, 0, NULL);
                break;

            case L'G':
                imageStarted = TRUE;
                guruScreen();
                break;

            case L'q':
            case L'Q':
                if (mayExit)
                    return EFI_SUCCESS;
        }

        if (imageStarted && mayExit && memoryTypeInformationVariableFound()) {
            mayExit = FALSE;
        }
    }
}
