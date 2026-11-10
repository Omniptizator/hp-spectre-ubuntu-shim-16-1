"""Bounded readers for the two binary formats used by the cookbook."""

import struct
import uuid

X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")


def pe_sections(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Not a PE image")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    symbols, nsymbols = struct.unpack_from("<II", data, pe + 12)
    strings = symbols + nsymbols * 18 if symbols else None
    start = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    if start + 40 * count > len(data):
        raise ValueError("Truncated PE section table")
    result = {}
    for index in range(count):
        offset = start + 40 * index
        name = data[offset:offset + 8].rstrip(b"\0")
        if name.startswith(b"/"):
            if strings is None:
                raise ValueError("Missing COFF string table")
            p = strings + int(name[1:])
            if not strings <= p < len(data):
                raise ValueError("Invalid COFF string offset")
            name = data[p:data.index(b"\0", p)]
        vsize = struct.unpack_from("<I", data, offset + 8)[0]
        size, raw = struct.unpack_from("<II", data, offset + 16)
        if raw + size > len(data):
            raise ValueError("Section outside image")
        decoded = name.decode("ascii")
        if decoded in result:
            raise ValueError("Duplicate PE section")
        result[decoded] = data[raw:raw + min(size, vsize)]
    return result


def signature_lists(data):
    offset = 0
    result = []
    while offset < len(data):
        if len(data) - offset < 28:
            raise ValueError("Truncated EFI signature list")
        kind = uuid.UUID(bytes_le=data[offset:offset + 16])
        size, hsize, ssize = struct.unpack_from("<III", data, offset + 16)
        if size < 28 + hsize or ssize < 16 or offset + size > len(data):
            raise ValueError("Invalid EFI signature list sizes")
        if (size - 28 - hsize) % ssize:
            raise ValueError("Incomplete EFI signature entry")
        header = data[offset + 28:offset + 28 + hsize]
        entries = [(uuid.UUID(bytes_le=data[p:p + 16]), data[p + 16:p + ssize])
                   for p in range(offset + 28 + hsize, offset + size, ssize)]
        result.append((kind, header, entries))
        offset += size
    return result


def make_signature_list(kind, entries, header=b""):
    if not entries or len({len(value) for _, value in entries}) != 1:
        raise ValueError("Require nonempty, equally sized signatures")
    ssize = 16 + len(entries[0][1])
    return (kind.bytes_le + struct.pack("<III", 28 + len(header) + len(entries) * ssize,
                                      len(header), ssize) + header
            + b"".join(owner.bytes_le + value for owner, value in entries))


def entry_set(data):
    return {(kind, header, value) for kind, header, entries in signature_lists(data)
            for _, value in entries}


def union_lists(*payloads):
    seen = set()
    result = b""
    for data in payloads:
        for kind, header, entries in signature_lists(data):
            missing = []
            for owner, value in entries:
                item = (kind, header, value)
                if item not in seen:
                    seen.add(item)
                    missing.append((owner, value))
            if missing:
                result += make_signature_list(kind, missing, header)
    return result
