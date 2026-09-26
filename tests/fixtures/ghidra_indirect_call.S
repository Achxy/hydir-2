.section .text
.globl hydir_leaf
.type hydir_leaf,@function
hydir_leaf:
  mov $7, %rax
  ret
.size hydir_leaf, .-hydir_leaf

.globl hydir_indirect
.type hydir_indirect,@function
hydir_indirect:
  call *%rax
  ret
.size hydir_indirect, .-hydir_indirect

.globl _start
.type _start,@function
_start:
  lea hydir_leaf(%rip), %rax
  call hydir_indirect
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
