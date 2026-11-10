# Third-party notices

The MIT license covers the original cookbook scripts, documentation, tests, and
VM fixtures in this repository. Downloaded software retains its own licenses:

- [shim](https://github.com/rhboot/shim), tag 16.1: see its `COPYRIGHT` and
  individual source-file notices, including Red Hat and Tianocore notices.
- [gnu-efi](https://github.com/rhboot/gnu-efi): see its source-file and license
  notices. This repository does not redistribute its source or libraries.
- Ubuntu/Canonical shim, GRUB, kernel, QEMU, OVMF, and packaging tools retain
  their respective upstream and distribution licenses.
- [Microsoft Secure Boot objects](https://github.com/microsoft/secureboot_objects):
  see the pinned upstream repository's license/usage terms. The historical
  Microsoft-authenticated dbx payload is fetched from a pinned packaging mirror;
  its hash and Microsoft signature are both checked.

The compatibility patch changes only the upstream unit-test copy of `lib/string.c`.
No production C/header patch is applied. Preserve upstream notices if you later
redistribute locally built binaries; this source-only cookbook does not grant
trademark rights or imply vendor endorsement.
