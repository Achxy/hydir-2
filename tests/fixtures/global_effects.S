.section .data
.globl hydir_counter
.type hydir_counter,@object
hydir_counter:
  .quad 0
.size hydir_counter, .-hydir_counter

.section .text
.globl hydir_leaf
.type hydir_leaf,@function
hydir_leaf:
  movq $7, hydir_counter(%rip)
  ret
.size hydir_leaf, .-hydir_leaf

.globl hydir_parent
.type hydir_parent,@function
hydir_parent:
  call hydir_leaf
  ret
.size hydir_parent, .-hydir_parent

.globl hydir_indirect
.type hydir_indirect,@function
hydir_indirect:
  call *%rax
  ret
.size hydir_indirect, .-hydir_indirect

.globl _start
.type _start,@function
_start:
  call hydir_parent
  mov $60, %rax
  xor %rdi, %rdi
  syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
