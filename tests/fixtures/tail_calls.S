.text

.globl hydir_tail_source
.type hydir_tail_source,@function
hydir_tail_source:
  jmp hydir_tail_target
.size hydir_tail_source, .-hydir_tail_source

.globl hydir_tail_target
.type hydir_tail_target,@function
hydir_tail_target:
  leaq 7(%rdi), %rax
  retq
.size hydir_tail_target, .-hydir_tail_target

.section .note.GNU-stack,"",@progbits
