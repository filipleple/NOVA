#!/usr/bin/env python3
"""
Host-side reference values for the NOVA DRTM probe.

  expected.py <nova-elf> <root.elf>

NOVA RIM   : same algorithm as nova/cmd/digest.cpp (the MLE region that the
             SINIT ACM hashes). Compare with the TXT_MLE_HASH event digest.
ROOT digest: SHA-256 over the root image's attestable region (first R-X
             PT_LOAD at file offset 0), which NOVA extends into PCR 19.
PCR19      : SHA256(0^32 || root digest), valid if NOVA's root measurement
             is the only extend of PCR 19 after SENTER.
"""

import hashlib
import struct
import sys

PT_LOAD = 1
PF_X, PF_W, PF_R = 1, 2, 4


def phdrs(img):
    if img[:4] != b"\x7fELF" or img[4] != 2:
        sys.exit("not an ELF64 file")
    e_phoff, = struct.unpack_from("<Q", img, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", img, 0x36)
    for i in range(e_phnum):
        yield struct.unpack_from("<IIQQQQQQ", img, e_phoff + i * e_phentsize)


def nova_rim(img):
    uuid = struct.pack("<QQ", 0x74a7476f9082ac5a, 0x42b651cba2555c0f)
    for off in range(0, len(img) - 52, 8):
        if img[off:off + 16] == uuid:
            size_, version, _entry, _first, mle_start, mle_end = struct.unpack_from("<IIIIII", img, off + 16)
            if size_ == 52 and version == 0x20003:
                break
    else:
        sys.exit("NOVA image has no MLE header")

    left, data = mle_end - mle_start, b""
    for p_type, _flags, p_offset, _va, _pa, p_filesz, _memsz, _align in phdrs(img):
        if not left:
            break
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        n = min(left, p_filesz)
        data += img[p_offset:p_offset + n]
        left -= n
    return data


def root_region(img):
    e_entry, e_phoff = struct.unpack_from("<QQ", img, 0x18)
    _, e_phnum = struct.unpack_from("<HH", img, 0x36)
    for p_type, flags, p_offset, p_vaddr, _pa, p_filesz, _memsz, _align in phdrs(img):
        if p_type != PT_LOAD or p_filesz == 0 or flags == 0:
            continue
        if ((flags & (PF_R | PF_W | PF_X)) == (PF_R | PF_X) and p_offset == 0 and p_filesz % 4096 == 0
                and e_phoff + e_phnum * 56 <= p_filesz and 0 <= e_entry - p_vaddr < p_filesz):
            return img[:p_filesz]
        break
    sys.exit("root image has no attestable region; NOVA would not measure it")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    nova = open(sys.argv[1], "rb").read()
    root = open(sys.argv[2], "rb").read()

    mle = nova_rim(nova)
    reg = root_region(root)
    rd = hashlib.sha256(reg).digest()

    print(f"NOVA RIM sha256 (expect as TXT_MLE_HASH digest): {hashlib.sha256(mle).hexdigest()}  ({len(mle)} bytes)")
    print(f"ROOT sha256 (expect as PCR19 EV_EVENT_TAG):       {rd.hex()}  ({len(reg)} bytes)")
    print(f"PCR19 expected:                                   {hashlib.sha256(bytes(32) + rd).hexdigest()}")


if __name__ == "__main__":
    main()
