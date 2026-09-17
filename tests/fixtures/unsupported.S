/* A valid function outside the M1 scalar instruction grammar. */
.text
.globl hydir_unsupported
.type hydir_unsupported, @function
hydir_unsupported:
    pushq %rbp
    movq %rsp, %rbp
    popq %rbp
    ret
.size hydir_unsupported, .-hydir_unsupported
.section .note.GNU-stack,"",@progbits
