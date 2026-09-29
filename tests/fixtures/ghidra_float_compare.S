.intel_syntax noprefix
.text

.global hydir_float_gate64
.type hydir_float_gate64, @function
hydir_float_gate64:
    ucomisd xmm0, xmm1
    jp .Lnan64
    jb .Lless64
    je .Lequal64
    mov eax, 3
    ret
.Lless64:
    mov eax, 1
    ret
.Lequal64:
    mov eax, 2
    ret
.Lnan64:
    mov eax, 4
    ret
.size hydir_float_gate64, .-hydir_float_gate64

.global hydir_float_gate32
.type hydir_float_gate32, @function
hydir_float_gate32:
    ucomiss xmm0, xmm1
    jp .Lnan32
    jb .Lless32
    je .Lequal32
    mov eax, 3
    ret
.Lless32:
    mov eax, 1
    ret
.Lequal32:
    mov eax, 2
    ret
.Lnan32:
    mov eax, 4
    ret
.size hydir_float_gate32, .-hydir_float_gate32

#ifndef HYDIR_FLOAT_HARNESS
.global _start
.type _start, @function
_start:
    xor edi, edi
    mov eax, 60
    syscall
.size _start, .-_start
#endif

.section .note.GNU-stack,"",@progbits
