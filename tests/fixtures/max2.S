/* Unsigned max; compare flags and a direct conditional branch. */
.text
.globl hydir_max2
.type hydir_max2, @function
hydir_max2:
    movq %rdi, %rax
    cmpq %rsi, %rdi
    jae .Ldone
    movq %rsi, %rax
.Ldone:
    ret
.size hydir_max2, .-hydir_max2
.section .note.GNU-stack,"",@progbits
