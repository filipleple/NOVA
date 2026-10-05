/*
 * Layout constraints imposed by NOVA on the root PD image (spec 6.2.1/6.2.2):
 *  - first PT_LOAD is R+X, starts at file offset 0 and covers the ELF header,
 *    the program headers and the entry point -> it becomes the attestable
 *    region measured into PCR 19
 *  - its p_filesz is a multiple of 4 KiB
 *  - every PT_LOAD has p_filesz == p_memsz (no .bss)
 *  - p_vaddr == p_offset (mod 4 KiB)
 */

ENTRY(_start)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS (5);   /* R-X */
    data PT_LOAD FLAGS (6);                 /* RW- */
}

SECTIONS
{
    . = 0x10000000 + SIZEOF_HEADERS;

    .text :
    {
        *(.text.start)
        *(.text .text.*)
        *(.rodata .rodata.*)
        . = ALIGN (4096);
    } :text

    .data :
    {
        *(.data .data.*)
        *(.bss .bss.*)
        *(COMMON)
        LONG (0)
        . = ALIGN (4096);
    } :data

    /DISCARD/ :
    {
        *(.eh_frame*) *(.note*) *(.comment) *(.got*) *(.interp) *(.dynamic)
    }
}
