/* Trusted patch refusal fixture: three bytes cannot hold a rel32 entry jump. */
.text
.globl hydir_add2
.type hydir_add2, @function
hydir_add2:
    xorl %eax, %eax
    ret
.size hydir_add2, .-hydir_add2
.section .note.GNU-stack,"",@progbits
