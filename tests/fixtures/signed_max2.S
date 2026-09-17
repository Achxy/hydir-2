/* Signed comparison over the same 64-bit input bit patterns. */
.text
.globl hydir_signed_max2
.type hydir_signed_max2, @function
hydir_signed_max2:
    movq %rdi, %rax
    cmpq %rsi, %rdi
    jge .Ldone
    movq %rsi, %rax
.Ldone:
    ret
.size hydir_signed_max2, .-hydir_signed_max2
.section .note.GNU-stack,"",@progbits
