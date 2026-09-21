/*
 * A deliberately small x86-64 ELF VM handler for the wiki worked example.
 * RDI points to VMState. The caller guarantees 2 <= sp <= 16.
 *
 *   offset 0:   uint64_t vreg[4]
 *   offset 32:  uint64_t stack[16]
 *   offset 160: uint64_t sp       (next free stack slot)
 *   offset 168: uint64_t vpc      (current one-byte opcode)
 *
 * vm_vadd replaces stack[sp-2] by stack[sp-2] + stack[sp-1], then
 * decrements sp and increments vpc. It does not erase stack[sp-1].
 */
.intel_syntax noprefix
.text
.global vm_vadd
.type vm_vadd, @function
vm_vadd:
    mov rcx, qword ptr [rdi + 160]
    mov rax, qword ptr [rdi + rcx*8 + 16]
    add rax, qword ptr [rdi + rcx*8 + 24]
    mov qword ptr [rdi + rcx*8 + 16], rax
    dec rcx
    mov qword ptr [rdi + 160], rcx
    inc qword ptr [rdi + 168]
    ret
.size vm_vadd, .-vm_vadd

/* An entry point makes the fixture a linked ELF; analysis selects vm_vadd. */
.global _start
.type _start, @function
_start:
    xor edi, edi
    mov eax, 60
    syscall
.size _start, .-_start
