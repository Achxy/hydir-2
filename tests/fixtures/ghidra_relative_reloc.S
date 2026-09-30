.section .data
.globl hydir_pointer
hydir_pointer:
  .quad hydir_target
.globl hydir_target
hydir_target:
  .quad 42

.section .text
.globl hydir_read_target
.type hydir_read_target,@function
hydir_read_target:
  mov hydir_pointer(%rip), %rax
  mov (%rax), %rax
  ret
.size hydir_read_target, .-hydir_read_target

.globl _start
.type _start,@function
_start:
  call hydir_read_target
  mov %rax, %rdi
  mov $60, %eax
  syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
