.text
.globl hydir_patch_target
.type hydir_patch_target, @function
hydir_patch_target:
    mov %rdi, %rax
    add %rsi, %rax
    ret
    .rept 16
    nop
    .endr
.size hydir_patch_target, .-hydir_patch_target
.section .note.GNU-stack,"",@progbits
