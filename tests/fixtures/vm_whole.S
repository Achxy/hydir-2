/* A small linked-ELF virtualized function. Every handler is a distinct host
 * function; the virtual program's branch and loop exist only in vm_bytecode.
 *
 * VMState at RDI: input, accumulator, counter, output pointer, unused VPC
 * slot, result (six 64-bit words). R12 is the live virtual PC.
 * Virtual opcodes: set, loop-test, add, increment, jump, odd-test, xor,
 * store, call-helper, halt. Operands are signed one-byte displacements or
 * unsigned immediates. A branch displacement is relative to its end.
 */
.intel_syntax noprefix
.text

.global vm_run
.type vm_run, @function
vm_run:
    push rbx
    push r12
    mov rbx, rdi
    mov qword ptr [rbx + 16], 0
    lea r12, [rip + vm_bytecode]
    jmp vm_dispatch
.size vm_run, .-vm_run

.global vm_dispatch
.type vm_dispatch, @function
vm_dispatch:
    movzx eax, byte ptr [r12]
    inc r12
    cmp eax, 1
    je vm_set
    cmp eax, 2
    je vm_loop_test
    cmp eax, 3
    je vm_add
    cmp eax, 4
    je vm_increment
    cmp eax, 5
    je vm_jump
    cmp eax, 6
    je vm_odd_test
    cmp eax, 7
    je vm_xor
    cmp eax, 8
    je vm_store
    cmp eax, 9
    je vm_call
    cmp eax, 10
    je vm_halt
    ud2
.size vm_dispatch, .-vm_dispatch

.global vm_set
.type vm_set, @function
vm_set:
    movzx eax, byte ptr [r12]
    inc r12
    mov qword ptr [rbx + 8], rax
    jmp vm_dispatch
.size vm_set, .-vm_set

.global vm_loop_test
.type vm_loop_test, @function
vm_loop_test:
    movsx rax, byte ptr [r12]
    inc r12
    mov rcx, qword ptr [rbx + 16]
    cmp rcx, qword ptr [rbx]
    jb .Lloop_continue
    add r12, rax
.Lloop_continue:
    jmp vm_dispatch
.size vm_loop_test, .-vm_loop_test

.global vm_add
.type vm_add, @function
vm_add:
    movzx eax, byte ptr [r12]
    inc r12
    add qword ptr [rbx + 8], rax
    jmp vm_dispatch
.size vm_add, .-vm_add

.global vm_increment
.type vm_increment, @function
vm_increment:
    inc qword ptr [rbx + 16]
    jmp vm_dispatch
.size vm_increment, .-vm_increment

.global vm_jump
.type vm_jump, @function
vm_jump:
    movsx rax, byte ptr [r12]
    inc r12
    add r12, rax
    jmp vm_dispatch
.size vm_jump, .-vm_jump

.global vm_odd_test
.type vm_odd_test, @function
vm_odd_test:
    movsx rax, byte ptr [r12]
    inc r12
    test qword ptr [rbx], 1
    jz .Leven
    add r12, rax
.Leven:
    jmp vm_dispatch
.size vm_odd_test, .-vm_odd_test

.global vm_xor
.type vm_xor, @function
vm_xor:
    movzx eax, byte ptr [r12]
    inc r12
    xor qword ptr [rbx + 8], rax
    jmp vm_dispatch
.size vm_xor, .-vm_xor

.global vm_store
.type vm_store, @function
vm_store:
    mov rdx, qword ptr [rbx + 24]
    mov rax, qword ptr [rbx + 8]
    mov qword ptr [rdx], rax
    jmp vm_dispatch
.size vm_store, .-vm_store

.global vm_call
.type vm_call, @function
vm_call:
    mov rdi, qword ptr [rbx + 8]
    call vm_helper
    mov qword ptr [rbx + 8], rax
    jmp vm_dispatch
.size vm_call, .-vm_call

.global vm_helper
.type vm_helper, @function
vm_helper:
    lea rax, [rdi + 1]
    ret
.size vm_helper, .-vm_helper

.global vm_halt
.type vm_halt, @function
vm_halt:
    mov rax, qword ptr [rbx + 8]
    mov qword ptr [rbx + 40], rax
    pop r12
    pop rbx
    ret
.size vm_halt, .-vm_halt

.global _start
.type _start, @function
_start:
    xor edi, edi
    mov eax, 60
    syscall
.size _start, .-_start

.section .rodata
.global vm_bytecode
vm_bytecode:
    .byte 1, 3                 /* acc = 3 */
.Lloop:
    .byte 2
    .byte .Lafter_loop - . - 1 /* if counter >= input: leave loop */
    .byte 3, 2                 /* acc += 2 */
    .byte 4                    /* counter++ */
    .byte 5
    .byte .Lloop - . - 1       /* repeat */
.Lafter_loop:
    .byte 6
    .byte .Lodd - . - 1        /* branch on input's low bit */
    .byte 3, 7                 /* even: acc += 7 */
    .byte 5
    .byte .Ljoin - . - 1
.Lodd:
    .byte 7, 0x55              /* odd: acc ^= 0x55 */
.Ljoin:
    .byte 8                    /* *output = acc */
    .byte 9                    /* acc = helper(acc) */
    .byte 10                   /* return acc */
.global vm_bytecode_end
vm_bytecode_end:
