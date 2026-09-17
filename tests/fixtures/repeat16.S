/* Bounded loop: exercises back-edge register and flag joins. */
.text
.globl hydir_repeat16
.type hydir_repeat16, @function
hydir_repeat16:
    movq $0, %rax
    movq $16, %rcx
.Lloop:
    addq %rdi, %rax
    subq $1, %rcx
    jne .Lloop
    ret
.size hydir_repeat16, .-hydir_repeat16
.section .note.GNU-stack,"",@progbits
