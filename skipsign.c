/*
 * grml-plus SkipSign - skip signature checking for loaded images
 *
 * Copyright 2014, Michael Schierl <schierlm@gmx.de>
 *
 * Based on the Linux Foundation's PreLoader, which is
 *
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * Licensed under version 2 of the GNU General Public Licence.
 *
 * For details see <http://git.kernel.org/cgit/linux/kernel/git/jejb/efitools.git/tree/COPYING>
 */

#include <efi.h>
#include <efilib.h>
#include <efierr.h>

#ifndef EFI_SECURITY_VIOLATION
#define EFI_SECURITY_VIOLATION EFIERR(26)
#endif

EFI_GUID SECURITY_PROTOCOL_GUID = { 0xA46423E3, 0x4617, 0x49f1, {0xB9, 0xFF, 0xD1, 0xBF, 0xA9, 0x11, 0x58, 0x39 } };
EFI_GUID SECURITY2_PROTOCOL_GUID = { 0x94ab2f58, 0x1438, 0x4ef1, {0x91, 0x52, 0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68 } };

/*
 * See the UEFI Platform Initialization manual (Vol2: DXE) for this
 */
struct _EFI_SECURITY2_PROTOCOL;
struct _EFI_SECURITY_PROTOCOL;
typedef struct _EFI_SECURITY2_PROTOCOL EFI_SECURITY2_PROTOCOL;
typedef struct _EFI_SECURITY_PROTOCOL EFI_SECURITY_PROTOCOL;
typedef EFI_DEVICE_PATH EFI_DEVICE_PATH_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_SECURITY_FILE_AUTHENTICATION_STATE) (const EFI_SECURITY_PROTOCOL *This, UINT32 AuthenticationStatus,
        const EFI_DEVICE_PATH_PROTOCOL *File);
typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION) (const EFI_SECURITY2_PROTOCOL *This, const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
        VOID *FileBuffer, UINTN FileSize, BOOLEAN BootPolicy);

struct _EFI_SECURITY2_PROTOCOL {
    EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};

struct _EFI_SECURITY_PROTOCOL {
    EFI_SECURITY_FILE_AUTHENTICATION_STATE  FileAuthenticationState;
};

static EFI_SECURITY_FILE_AUTHENTICATION_STATE esfas = NULL;
static EFI_SECURITY2_FILE_AUTHENTICATION es2fa = NULL;

static EFI_STATUS thunk_security_policy_authentication(const EFI_SECURITY_PROTOCOL *This, UINT32 AuthenticationStatus,
        const EFI_DEVICE_PATH_PROTOCOL *DevicePath)
__attribute__((unused));

static EFI_STATUS thunk_security2_policy_authentication(const EFI_SECURITY2_PROTOCOL *This, const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
        VOID *FileBuffer, UINTN FileSize, BOOLEAN BootPolicy)
__attribute__((unused));

static __attribute__((used)) EFI_STATUS security2_policy_authentication (const EFI_SECURITY2_PROTOCOL *This, const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
        VOID *FileBuffer, UINTN FileSize, BOOLEAN BootPolicy) {
    EFI_STATUS status;

    status = uefi_call_wrapper(es2fa, 5, This, DevicePath, FileBuffer, FileSize, BootPolicy);

    if (status == EFI_SECURITY_VIOLATION || status == EFI_ACCESS_DENIED)
        status = EFI_SUCCESS;

    return status;
}

static __attribute__((used)) EFI_STATUS security_policy_authentication (const EFI_SECURITY_PROTOCOL *This, UINT32 AuthenticationStatus,
        const EFI_DEVICE_PATH_PROTOCOL *DevicePathConst) {
    EFI_STATUS status;

    status = uefi_call_wrapper(esfas, 3, This, AuthenticationStatus, DevicePathConst);

    if (status == EFI_SECURITY_VIOLATION || status == EFI_ACCESS_DENIED)
        status = EFI_SUCCESS;

    return status;
}


/* Nasty: ELF and EFI have different calling conventions.  Here is the map for
 * calling ELF -> EFI
 *
 *   1) rdi -> rcx (32 saved)
 *   2) rsi -> rdx (32 saved)
 *   3) rdx -> r8 ( 32 saved)
 *   4) rcx -> r9 (32 saved)
 *   5) r8 -> 32(%rsp) (48 saved)
 *   6) r9 -> 40(%rsp) (48 saved)
 *   7) pad+0(%rsp) -> 48(%rsp) (64 saved)
 *   8) pad+8(%rsp) -> 56(%rsp) (64 saved)
 *   9) pad+16(%rsp) -> 64(%rsp) (80 saved)
 *  10) pad+24(%rsp) -> 72(%rsp) (80 saved)
 *  11) pad+32(%rsp) -> 80(%rsp) (96 saved)

 *
 * So for a five argument callback, the map is ignore the first two arguments
 * and then map (EFI -> ELF) assuming pad = 0.
 *
 * ARG4  -> ARG1
 * ARG3  -> ARG2
 * ARG5  -> ARG3
 * ARG6  -> ARG4
 * ARG11 -> ARG5
 *
 * Calling conventions also differ over volatile and preserved registers in
 * MS: RBX, RBP, RDI, RSI, R12, R13, R14, and R15 are considered nonvolatile .
 * In ELF: Registers %rbp, %rbx and %r12 through %r15 “belong” to the calling
 * function and the called function is required to preserve their values.
 *
 * This means when accepting a function callback from MS -> ELF, we have to do
 * separate preservation on %rdi, %rsi before swizzling the arguments and
 * handing off to the ELF function.
 */

asm (
".type security2_policy_authentication,@function\n"
"thunk_security2_policy_authentication:\n\t"
    "mov    0x28(%rsp), %r10    # ARG5\n\t"
    "push    %rdi\n\t"
    "push    %rsi\n\t"
    "mov    %r10, %rdi\n\t"
    "subq    $8, %rsp    # space for storing stack pad\n\t"
    "mov    $0x08, %rax\n\t"
    "mov    $0x10, %r10\n\t"
    "and    %rsp, %rax\n\t"
    "cmovnz    %rax, %r11\n\t"
    "cmovz    %r10, %r11\n\t"
    "subq    %r11, %rsp\n\t"
    "addq    $8, %r11\n\t"
    "mov    %r11, (%rsp)\n\t"
"# five argument swizzle\n\t"
    "mov    %rdi, %r10\n\t"
    "mov    %rcx, %rdi\n\t"
    "mov    %rdx, %rsi\n\t"
    "mov    %r8, %rdx\n\t"
    "mov    %r9, %rcx\n\t"
    "mov    %r10, %r8\n\t"
    "callq    security2_policy_authentication@PLT\n\t"
    "mov    (%rsp), %r11\n\t"
    "addq    %r11, %rsp\n\t"
    "pop    %rsi\n\t"
    "pop    %rdi\n\t"
    "ret\n"
);

asm (
".type security_policy_authentication,@function\n"
"thunk_security_policy_authentication:\n\t"
    "push    %rdi\n\t"
    "push    %rsi\n\t"
    "subq    $8, %rsp    # space for storing stack pad\n\t"
    "mov    $0x08, %rax\n\t"
    "mov    $0x10, %r10\n\t"
    "and    %rsp, %rax\n\t"
    "cmovnz    %rax, %r11\n\t"
    "cmovz    %r10, %r11\n\t"
    "subq    %r11, %rsp\n\t"
    "addq    $8, %r11\n\t"
    "mov    %r11, (%rsp)\n\t"
"# three argument swizzle\n\t"
    "mov    %rcx, %rdi\n\t"
    "mov    %rdx, %rsi\n\t"
    "mov    %r8, %rdx\n\t"
    "callq    security_policy_authentication@PLT\n\t"
    "mov    (%rsp), %r11\n\t"
    "addq    %r11, %rsp\n\t"
    "pop    %rsi\n\t"
    "pop    %rdi\n\t"
    "ret\n"
);

EFI_STATUS security_policy_install(void) {
    EFI_SECURITY_PROTOCOL *security_protocol;
    EFI_SECURITY2_PROTOCOL *security2_protocol = NULL;
    EFI_STATUS status;

    if (esfas)
        /* Already Installed */
        return EFI_ALREADY_STARTED;

    /* Don't bother with status here.  The call is allowed
     * to fail, since SECURITY2 was introduced in PI 1.2.1
     * If it fails, use security2_protocol == NULL as indicator */
    LibLocateProtocol(&SECURITY2_PROTOCOL_GUID, &security2_protocol);

    status = LibLocateProtocol(&SECURITY_PROTOCOL_GUID, &security_protocol);
    if (status != EFI_SUCCESS)
        /* This one is mandatory, so there's a serious problem */
        return status;

    if (security2_protocol) {
        es2fa = security2_protocol->FileAuthentication;
        security2_protocol->FileAuthentication = thunk_security2_policy_authentication;
        /* check for security policy in write protected memory */
        if (security2_protocol->FileAuthentication != thunk_security2_policy_authentication)
            return EFI_ACCESS_DENIED;
    }

    esfas = security_protocol->FileAuthenticationState;
    security_protocol->FileAuthenticationState = thunk_security_policy_authentication;
    /* check for security policy in write protected memory */
    if (security_protocol->FileAuthenticationState != thunk_security_policy_authentication)
        return EFI_ACCESS_DENIED;

    return EFI_SUCCESS;
}

EFI_STATUS security_policy_uninstall(void) {
    EFI_STATUS status;

    if (esfas) {
        EFI_SECURITY_PROTOCOL *security_protocol;

        status = LibLocateProtocol(&SECURITY_PROTOCOL_GUID, &security_protocol);

        if (status != EFI_SUCCESS)
            return status;

        security_protocol->FileAuthenticationState = esfas;
        esfas = NULL;
    } else {
        /* nothing installed */
        return EFI_NOT_STARTED;
    }

    if (es2fa) {
        EFI_SECURITY2_PROTOCOL *security2_protocol;

        status = LibLocateProtocol(&SECURITY2_PROTOCOL_GUID, &security2_protocol);

        if (status != EFI_SUCCESS)
            return status;

        security2_protocol->FileAuthentication = es2fa;
        es2fa = NULL;
    }

    return EFI_SUCCESS;
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

EFI_STATUS EFIAPI efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;

    InitializeLib(ImageHandle, SystemTable);

    status = security_policy_install();
    if (status != EFI_SUCCESS) {
        Print(L"Failed to install override security policy.");
    }

    runImage(ImageHandle, L"protector.efi");

    status = security_policy_uninstall();
    if (status != EFI_SUCCESS)
        Print(L"Failed to uninstall override security policy.");

    return EFI_SUCCESS;
}
