/* SPDX-License-Identifier: MIT
 * VM ONLY. Never install this fixture on a hardware ESP.
 */
#include <efi.h>
#include <efilib.h>

typedef struct {
    EFI_STATUS (*verify)(VOID *, UINT32); /* shim_lock uses the historical C ABI. */
    VOID *hash;
    VOID *context;
} SHIM_LOCK;

static EFI_GUID lock_guid = {0x605dab50, 0xe046, 0x4300,
                            {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}};

static void message(const char *s)
{
    while (*s) {
        __asm__ volatile ("outb %0, $0xe9" : : "a"(*s));
        s++;
    }
}

static void finish(UINT32 value)
{
    __asm__ volatile ("outl %0, %1" : : "a"(value), "Nd"((UINT16)0xf4));
    for (;;) __asm__ volatile ("hlt");
}

static EFI_STATUS read_file(EFI_FILE *root, CHAR16 *name, VOID **buffer, UINT32 *size)
{
    EFI_FILE *file = NULL;
    EFI_FILE_INFO *info;
    UINTN length;
    EFI_STATUS status = uefi_call_wrapper(root->Open, 5, root, &file, name, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) return status;
    info = LibFileInfo(file);
    if (!info || info->FileSize > 32 * 1024 * 1024) return EFI_LOAD_ERROR;
    length = info->FileSize;
    FreePool(info);
    *buffer = AllocatePool(length);
    if (!*buffer) return EFI_OUT_OF_RESOURCES;
    status = uefi_call_wrapper(file->Read, 3, file, &length, *buffer);
    uefi_call_wrapper(file->Close, 1, file);
    *size = length;
    return status;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table)
{
    EFI_GUID global = EFI_GLOBAL_VARIABLE;
    EFI_GUID loaded_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_LOADED_IMAGE *loaded = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
    EFI_FILE *root = NULL;
    SHIM_LOCK *lock = NULL;
    UINT8 secure = 0, setup = 1;
    UINTN length = 1;
    EFI_STATUS status;
    unsigned i;
    struct {
        CHAR16 *path;
        const char *name;
        EFI_STATUS expected;
    } tests[] = {
        {L"\\canonical.efi", "Canonical GRUB", EFI_SUCCESS},
        {L"\\manager.efi", "matching MokManager", EFI_SUCCESS},
        {L"\\unsigned.efi", "unsigned rejection", EFI_SECURITY_VIOLATION},
        {L"\\tampered.efi", "tampered rejection", EFI_SECURITY_VIOLATION},
        {L"\\revoked.efi", "SBAT rejection", EFI_SECURITY_VIOLATION},
        {L"\\forbidden.efi", "dbx hash rejection", EFI_SECURITY_VIOLATION},
    };
    InitializeLib(image, table);
    message("PROBE START\n");
    status = uefi_call_wrapper(RT->GetVariable, 5, L"SecureBoot", &global, NULL, &length, &secure);
    if (EFI_ERROR(status) || secure != 1) { message("FAIL SecureBoot\n"); finish(1); }
    length = 1;
    status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &global, NULL, &length, &setup);
    if (EFI_ERROR(status) || setup != 0) { message("FAIL SetupMode\n"); finish(1); }
    message("PASS SecureBoot=1 SetupMode=0\n");
    status = uefi_call_wrapper(BS->LocateProtocol, 3, &lock_guid, NULL, &lock);
    if (EFI_ERROR(status) || !lock) { message("FAIL shim_lock missing\n"); finish(1); }
    status = uefi_call_wrapper(BS->HandleProtocol, 3, image, &loaded_guid, &loaded);
    if (EFI_ERROR(status)) finish(1);
    status = uefi_call_wrapper(BS->HandleProtocol, 3, loaded->DeviceHandle, &fs_guid, &fs);
    if (EFI_ERROR(status)) finish(1);
    status = uefi_call_wrapper(fs->OpenVolume, 2, fs, &root);
    if (EFI_ERROR(status)) finish(1);
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        VOID *buffer = NULL;
        UINT32 size = 0;
        status = read_file(root, tests[i].path, &buffer, &size);
        if (EFI_ERROR(status)) { message("FAIL reading fixture\n"); finish(1); }
        status = lock->verify(buffer, size);
        FreePool(buffer);
        message(status == tests[i].expected ? "PASS " : "FAIL ");
        message(tests[i].name);
        message("\n");
        if (status != tests[i].expected) finish(1);
    }
    message("ALL PASS\n");
    finish(0);
    return EFI_SUCCESS;
}
