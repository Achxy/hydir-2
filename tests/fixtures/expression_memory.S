.text
.globl hydir_expression_memory
.type hydir_expression_memory,@function
hydir_expression_memory:
    mov (%rdi), %eax
    mov %al, 1(%rdi)
    mov 2(%rdi), %al
    mov (%rsp), %rcx
    mov %rcx, -8(%rsp)
    mov (%eax), %r8
    mov %fs:0, %rdx
    lea 16(%rdi,%rsi,8), %r9
    lea 16(%rdi,%rsi,8), %r10d
    ret
.size hydir_expression_memory, .-hydir_expression_memory
