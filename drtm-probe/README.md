# drtm-probe

A minimal NOVA root PD that checks whether NOVA was started through an Intel
TXT measured launch (GETSEC[SENTER]). It reads PCR17-19 (SHA-256 bank) from
the TPM, replays the DRTM event log that NOVA exposes through the HIP and
compares the two. All output goes to the legacy UART at I/O port 0x3f8.

NOVA performs the launch itself, no tboot is involved. The firmware must place
a matching SINIT ACM at TXT.SINIT.BASE beforehand.

## Files

- `main.c` - the probe: takes the TPM and event log regions from NOVA, reads
  PCR17-19 via TIS/FIFO or CRB, parses the TCG crypto-agile log, replays the
  SHA-256 digests and prints a verdict.
- `start.S` - entry point, sets up a stack and passes the HIP pointer to
  `root_main`.
- `root.ld` - linker script that produces the image layout NOVA requires for
  the root PD. The first R-X segment is the region NOVA measures into PCR19.
- `expected.py` - computes reference values on the host: the NOVA MLE hash
  (TXT_MLE_HASH event), the root PD digest and the expected PCR19.
- `grub.cfg` - multiboot2 entry loading NOVA with `root.elf` as module.
- `Makefile` - `make` builds `root.elf`, `make expected` runs `expected.py`,
  `make usb` builds a GRUB EFI boot tree in `usb/`.

## Usage

    make -C .. ARCH=x86_64          # build NOVA
    make                            # build root.elf (UART=0x2f8 to change port)
    make usb                        # copy usb/ to a FAT32 partition and boot it
    make expected                   # reference digests to compare with the log

## Result

Protectli VP2430 (Intel N150, Alder Lake-N), coreboot + EDK2 with TXT,
Infineon SLB9670 TPM 2.0, NOVA 7812027.

NOVA after the launch:

    [ -1] TPM2: 15d1:001b IFX SLB9670 v7.85 FIFO REV:138 ALG:2 PCR:24 MAX:1420/1420
    [ -1] DRTM: 8086:b00c (0x1) 8086:5481 (PRD)
    [ -1] DRTM: DPR:0x7b400000/0x400000 SINIT:0x7b6c0000/0x50000 HEAP:0x7b710000/0xf0000
    [ -1] DRTM: ACM-MLE v9:  658
    [ -1] DRTM: TPM-LOG v2: 1620
    [  0] ROOT: Invoking entry point 0x100000c0 after measuring 0x2000 bytes

The probe (event list shortened):

    ROOT-PD: TPM: FIFO/TIS interface, VID:DID 15d1:001b
    ROOT-PD: PCR17 sha256 38a374347988ebae1d18f2969edf8ae261297b69b327f846c2038bb80bdfac00
    ROOT-PD: PCR18 sha256 ce02ebc9ae3013f0e6e376d2f49ae56f6d3b570d7f97cf081304e1d253f5098b
    ROOT-PD: PCR19 sha256 895e99355b920ad724430217a4dbf775de370c1c2f8db5de8b5fcef4dfe76191
    ROOT-PD: LOG: #0 PCR17 type 0x402 TXT_HASH_START
    ROOT-PD: LOG: #10 PCR17 type 0x404 TXT_MLE_HASH
    ROOT-PD: LOG: #12 PCR18 type 0x410 TXT_SINIT_PUBKEY_HASH
    ROOT-PD: LOG: #18 PCR19 type 0x006 EV_EVENT_TAG (NOVA)
    ROOT-PD: LOG: 19 events
    ROOT-PD: REPLAY PCR17 38a374347988ebae1d18f2969edf8ae261297b69b327f846c2038bb80bdfac00  MATCH
    ROOT-PD: REPLAY PCR18 ce02ebc9ae3013f0e6e376d2f49ae56f6d3b570d7f97cf081304e1d253f5098b  MATCH
    ROOT-PD: REPLAY PCR19 895e99355b920ad724430217a4dbf775de370c1c2f8db5de8b5fcef4dfe76191  MATCH
    ROOT-PD: VERDICT: DRTM OK - PCR17 was reset by SENTER and PCR17/18/19 match the event log replay

PCR17 starts at all ones after a platform reset and only SENTER resets it to
zero, so a PCR17 that replays from zero is proof of the measured launch. The
STM and LCP events carry SHA-256 of a single zero byte, meaning no STM and no
Launch Control Policy are provisioned on this platform.
