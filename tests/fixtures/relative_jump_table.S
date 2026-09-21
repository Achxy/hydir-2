.intel_syntax noprefix

.text
.globl relative_table_dispatch
.type relative_table_dispatch, @function
relative_table_dispatch:
    cmp edi, 3
    ja .Ldefault
    lea rax, [rip + .Ltable]
    movsxd rcx, dword ptr [rax + rdi * 4]
    add rcx, rax
    jmp rcx
.Lcase0:
    mov eax, 10
    ret
.Lcase1:
    mov eax, 20
    ret
.Lcase2:
    mov eax, 30
    ret
.Lcase3:
    mov eax, 40
    ret
.Ldefault:
    xor eax, eax
    ret
.size relative_table_dispatch, .-relative_table_dispatch

.section .rodata,"a",@progbits
.p2align 2
.Ltable:
    .long .Lcase0 - .Ltable
    .long .Lcase1 - .Ltable
    .long .Lcase2 - .Ltable
    .long .Lcase3 - .Ltable

.section .note.GNU-stack,"",@progbits
