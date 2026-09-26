/* A real x86-64 ELF source for raw P-code add-zero rewrite coverage. */
.text
.globl hydir_add_zero
.type hydir_add_zero, @function
hydir_add_zero:
    movq %rdi, %rax
    addq $0, %rax
    ret
.size hydir_add_zero, .-hydir_add_zero

.globl _start
.type _start, @function
_start:
    movq $60, %rax
    xorq %rdi, %rdi
    syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
