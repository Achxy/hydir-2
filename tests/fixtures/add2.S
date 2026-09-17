/* Trusted M1 fixture. Exact bytes matter; the lifter never reads this source. */
.text
.globl hydir_add2
.type hydir_add2, @function
hydir_add2:
    leaq (%rdi,%rsi), %rax
    ret
.size hydir_add2, .-hydir_add2
.section .note.GNU-stack,"",@progbits
