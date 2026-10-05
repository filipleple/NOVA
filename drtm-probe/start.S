/*
 * NOVA root PD entry (x86_64)
 *
 * On entry (NOVA spec 8.1.2):
 *   RSP = HVA of the Hypervisor Information Page (HIP)
 *   RDI/RSI/RDX = EAX/EBX/ECX at boot time (Multiboot magic/info)
 */

.section .text.start, "ax"
.global _start
_start:
        mov     %rsp, %rdi              // arg0 = HIP
        lea     stack_top(%rip), %rsp
        call    root_main
1:      pause
        jmp     1b

// The stack lives in .data, not .bss: NOVA requires p_filesz == p_memsz
.section .data
.balign 16
stack:  .skip   16384
stack_top:
