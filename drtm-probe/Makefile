#
# NOVA root PD: DRTM attestation probe
#
#   make                      # build root.elf (UART at I/O port 0x3f8)
#   make UART=0x2f8           # different legacy UART base
#   make expected             # reference digests (NOVA RIM, root digest, PCR19)
#   make usb                  # ./usb tree: GRUB EFI + NOVA + root.elf
#

CC      ?= gcc
UART    ?= 0x3f8
NOVA    ?= ../build-x86_64/x86_64-nova
GRUB_MKSTANDALONE ?= $(shell command -v grub2-mkstandalone || command -v grub-mkstandalone)

CFLAGS  := -std=gnu11 -Os -Wall -Wextra -ffreestanding -fno-builtin -nostdlib \
           -fno-pic -fno-pie -mcmodel=small -mgeneral-regs-only -mno-red-zone \
           -fno-stack-protector -fno-asynchronous-unwind-tables \
           -fno-zero-initialized-in-bss -DUART_PIO=$(UART)
LDFLAGS := -static -no-pie -nostdlib -Wl,--build-id=none -Wl,-z,max-page-size=0x1000 \
           -Wl,-z,noexecstack -Wl,-T,root.ld

root.elf: start.S main.c root.ld Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) start.S main.c -o $@
	@readelf -lW $@ | sed -n '/Program Headers/,/^$$/p'

GRUB_EFI_DIR      ?= $(firstword $(wildcard /usr/lib/grub/x86_64-efi /usr/lib64/grub/x86_64-efi))

usb: root.elf grub.cfg
	@test -n "$(GRUB_MKSTANDALONE)" || { echo "grub-mkstandalone not found (Fedora: grub2-tools-extra, Debian/Ubuntu: grub-common)"; exit 1; }
	@test -f "$(GRUB_EFI_DIR)/modinfo.sh" || { echo "GRUB x86_64-efi modules missing (Fedora: sudo dnf install grub2-efi-x64-modules, Debian/Ubuntu: sudo apt install grub-efi-amd64-bin)"; exit 1; }
	rm -rf usb && mkdir -p usb/EFI/BOOT usb/nova
	$(GRUB_MKSTANDALONE) -O x86_64-efi -d $(GRUB_EFI_DIR) -o usb/EFI/BOOT/BOOTX64.EFI \
	    --modules="part_gpt part_msdos fat search search_fs_file multiboot2 serial terminal normal configfile" \
	    "boot/grub/grub.cfg=grub.cfg"
	cp $(NOVA) usb/nova/x86_64-nova
	cp root.elf usb/nova/root.elf
	@echo "USB tree ready in ./usb - copy its contents to a FAT32 partition"

expected: root.elf
	python3 expected.py $(NOVA) root.elf

clean:
	rm -rf root.elf usb

.PHONY: usb expected clean
