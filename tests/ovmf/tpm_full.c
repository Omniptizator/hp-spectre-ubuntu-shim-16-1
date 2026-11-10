/* SPDX-License-Identifier: MIT
 * VM ONLY. Inject EFI_VOLUME_FULL after a simulated measurement.
 */
#define GNU_EFI_USE_MS_ABI
#include <efi.h>
#include <efilib.h>
#include <stdint.h>
#include "tpm.h"

static void message(const char *s)
{
    while (*s) {
        __asm__ volatile ("outb %0, $0xe9" : : "a"(*s));
        s++;
    }
}

static EFI_STATUS EFIAPI caps(struct efi_tpm2_protocol *self,
                              EFI_TCG2_BOOT_SERVICE_CAPABILITY *capability)
{
    (void)self;
    SetMem(capability, sizeof(*capability), 0);
    capability->Size = sizeof(*capability);
    capability->StructureVersion.Major = 1;
    capability->StructureVersion.Minor = 1;
    capability->ProtocolVersion.Major = 1;
    capability->ProtocolVersion.Minor = 1;
    capability->HashAlgorithmBitmap = 2;
    capability->SupportedEventLogs = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
    capability->TPMPresentFlag = TRUE;
    capability->NumberOfPcrBanks = 1;
    capability->ActivePcrBanks = 2;
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI full(struct efi_tpm2_protocol *self, uint64_t flags,
                              EFI_PHYSICAL_ADDRESS data, uint64_t size,
                              EFI_TCG2_EVENT *event)
{
    (void)self; (void)flags; (void)data; (void)size; (void)event;
    message("INJECT EFI_VOLUME_FULL\n");
    return EFI_VOLUME_FULL;
}

static efi_tpm2_protocol_t fake = {.get_capability = caps, .hash_log_extend_event = full};

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table)
{
    EFI_GUID tcg2 = {0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}};
    EFI_GUID loaded_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_HANDLE handle = NULL, child = NULL;
    EFI_LOADED_IMAGE *loaded = NULL;
    VOID *existing = NULL;
    EFI_DEVICE_PATH *path;
    EFI_STATUS status;
    InitializeLib(image, table);
    status = BS->LocateProtocol(&tcg2, NULL, &existing);
    if (!EFI_ERROR(status)) { message("FAIL real TPM protocol present\n"); return EFI_ABORTED; }
    status = BS->InstallProtocolInterface(&handle, &tcg2, EFI_NATIVE_INTERFACE, &fake);
    if (EFI_ERROR(status)) { message("FAIL protocol install\n"); return status; }
    status = BS->HandleProtocol(image, &loaded_guid, (VOID **)&loaded);
    if (EFI_ERROR(status)) return status;
    path = FileDevicePath(loaded->DeviceHandle, L"\\EFI\\BOOT\\shimx64.efi");
    status = BS->LoadImage(FALSE, image, path, NULL, 0, &child);
    if (EFI_ERROR(status)) { message("FAIL shim load\n"); return status; }
    message("START SHIM WITH SIMULATED FULL TPM LOG\n");
    return BS->StartImage(child, NULL, NULL);
}
